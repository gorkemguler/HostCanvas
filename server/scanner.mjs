import {
  ALLOW_PRIVATE_TARGETS,
  APP_NAME,
  APP_VERSION,
  MAX_CONCURRENT_SCANS,
  SCHEDULER_INTERVAL_MS,
} from './config.mjs';
import {
  createScan,
  finishScan,
  getAsset,
  getDueAssets,
  listAssets,
  listQueuedScans,
  markScanRunning,
  reconcileIncidents,
  recoverInterruptedScans,
} from './db.mjs';
import { probePublicDns } from './probes/dns.mjs';
import {
  getTestsslInfo,
  runTestssl,
  stopTestsslProcesses,
} from './probes/testssl.mjs';
import { probeHttpHeaders, probeTls } from './probes/tls.mjs';
import { evaluateObservations, gradeEvaluations } from './rules/index.mjs';
import { dispatchIncidentNotifications } from './notifications.mjs';
import { resolveAndValidateTarget } from './security/targets.mjs';

const running = new Map();
let schedulerTimer;
let stopping = false;

function safeError(error) {
  return {
    code: error.code || 'SCAN_FAILED',
    message: String(error.message || 'Tarama başarısız oldu.').slice(0, 1_000),
  };
}

async function executeScan(scan) {
  const asset = getAsset(scan.assetId);
  if (!asset || !asset.enabled) {
    finishScan(scan.id, {
      status: 'failed',
      errorCode: 'ASSET_UNAVAILABLE',
      errorMessage: 'Varlık bulunamadı veya arşivlenmiş.',
    });
    return;
  }

  try {
    const allowPrivate = ALLOW_PRIVATE_TARGETS && asset.allowPrivate;
    const resolved = await resolveAndValidateTarget(asset.hostname, {
      allowPrivate,
    });
    const target = {
      hostname: asset.hostname,
      port: asset.port,
      address: resolved.address,
      family: resolved.family,
    };

    const [tlsObservation, httpObservation, publicDnsObservation] =
      await Promise.all([
        probeTls(target),
        probeHttpHeaders(target),
        probePublicDns(asset.hostname),
      ]);

    const observations = {
      schemaVersion: 1,
      collectedAt: new Date().toISOString(),
      target: {
        hostname: asset.hostname,
        port: asset.port,
        address: resolved.address,
        family: resolved.family,
        resolvedAddresses: resolved.records,
      },
      tls: tlsObservation,
      http: httpObservation,
      publicDns: publicDnsObservation,
      testssl: null,
    };

    if (!getAsset(scan.assetId)?.enabled) {
      finishScan(scan.id, {
        status: 'failed',
        errorCode: 'ASSET_ARCHIVED_DURING_SCAN',
        errorMessage: 'Varlık tarama sırasında arşivlendi.',
        observations,
      });
      return;
    }

    let scanStatus = 'succeeded';
    let testsslVersion = null;
    if (scan.profile === 'deep') {
      observations.testssl = await runTestssl(target, scan.id);
      testsslVersion = observations.testssl.engineVersion;
      if (observations.testssl.status !== 'complete') scanStatus = 'partial';
    }

    if (!getAsset(scan.assetId)?.enabled) {
      finishScan(scan.id, {
        status: 'failed',
        errorCode: 'ASSET_ARCHIVED_DURING_SCAN',
        errorMessage: 'Varlık tarama sırasında arşivlendi.',
        observations,
      });
      return;
    }

    const evaluations = evaluateObservations(observations, asset);
    const grade = gradeEvaluations(evaluations);
    const scannerVersion = testsslVersion
      ? `${APP_NAME} ${APP_VERSION} · testssl.sh ${testsslVersion}`
      : `${APP_NAME} ${APP_VERSION} · Node ${process.version}`;

    finishScan(scan.id, {
      status: scanStatus,
      grade,
      scannerVersion,
      observations: { ...observations, evaluations },
    });
    const notificationEvents = reconcileIncidents(
      asset.id,
      scan.id,
      evaluations,
      {
        completePrefixes:
          scan.profile === 'deep' && observations.testssl?.status === 'complete'
            ? ['testssl.']
            : [],
      },
    );
    try {
      await dispatchIncidentNotifications(notificationEvents);
    } catch (error) {
      console.error(
        '[notifications]',
        String(error.message || error).slice(0, 500),
      );
    }
  } catch (error) {
    const safe = safeError(error);
    finishScan(scan.id, {
      status: 'failed',
      errorCode: safe.code,
      errorMessage: safe.message,
      scannerVersion: `${APP_NAME} ${APP_VERSION}`,
    });
  }
}

export function pumpQueue() {
  if (stopping) return;
  const available = Math.max(0, MAX_CONCURRENT_SCANS - running.size);
  if (!available) return;

  for (const queued of listQueuedScans(available)) {
    const claimed = markScanRunning(queued.id);
    if (!claimed) continue;
    const task = executeScan(claimed)
      .catch(() => undefined)
      .finally(() => {
        running.delete(claimed.id);
        setImmediate(pumpQueue);
      });
    running.set(claimed.id, task);
  }
}

export function queueAssetScan(assetId, options = {}) {
  const asset = getAsset(assetId);
  if (!asset) {
    const error = new Error('Varlık bulunamadı.');
    error.code = 'ASSET_NOT_FOUND';
    throw error;
  }
  if (!asset.enabled) {
    const error = new Error('Arşivlenmiş varlık taranamaz.');
    error.code = 'ASSET_ARCHIVED';
    throw error;
  }
  const profile = options.profile || asset.scanProfile;
  if (!['native', 'deep'].includes(profile)) {
    const error = new Error('Tarama profili geçersiz.');
    error.code = 'INVALID_SCAN_PROFILE';
    throw error;
  }
  const result = createScan(assetId, profile, options.trigger || 'manual');
  setImmediate(pumpQueue);
  return result;
}

export function queueAllAssets(options = {}) {
  const results = [];
  for (const asset of listAssets()) {
    results.push(queueAssetScan(asset.id, options));
  }
  return results;
}

function scheduleDueAssets() {
  for (const asset of getDueAssets()) {
    queueAssetScan(asset.id, {
      profile: asset.scanProfile,
      trigger: asset.lastScanAt ? 'scheduled' : 'initial',
    });
  }
}

export async function scannerHealth() {
  const testssl = await getTestsslInfo();
  return {
    native: { available: true, version: process.version },
    testssl,
    running: running.size,
    concurrency: MAX_CONCURRENT_SCANS,
  };
}

export function startScanner() {
  stopping = false;
  recoverInterruptedScans();
  scheduleDueAssets();
  pumpQueue();
  schedulerTimer = setInterval(scheduleDueAssets, SCHEDULER_INTERVAL_MS);
  schedulerTimer.unref();
}

export async function stopScanner() {
  stopping = true;
  if (schedulerTimer) clearInterval(schedulerTimer);
  stopTestsslProcesses();
  await Promise.allSettled(running.values());
}
