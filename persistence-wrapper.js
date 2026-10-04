import 'dotenv/config';

import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import Database from 'better-sqlite3';
import pg from 'pg';

const { Pool } = pg;

const dbPath = path.resolve(
  process.env.SQLITE_PATH || 'in2u.db'
);

const snapshotPath = path.join(
  process.cwd(),
  '.in2u-postgres-snapshot.db'
);

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 2
    })
  : null;

async function prepareStore() {
  if (!pool) {
    console.warn(
      'DATABASE_URL is not set. In2U will run with local SQLite only.'
    );
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS in2u_sqlite_snapshot (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      data BYTEA NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const result = await pool.query(
    'SELECT data FROM in2u_sqlite_snapshot WHERE id=1'
  );

  if (result.rows.length && result.rows[0].data) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });

    fs.writeFileSync(
      dbPath,
      Buffer.from(result.rows[0].data)
    );

    for (const suffix of ['-wal', '-shm']) {
      try {
        fs.rmSync(dbPath + suffix, { force: true });
      } catch {}
    }

    console.log(
      'In2U SQLite database restored from Postgres snapshot.'
    );
  }
}

async function saveSnapshot() {
  if (!pool || !fs.existsSync(dbPath)) return;

  try {
    fs.rmSync(snapshotPath, { force: true });

    const source = new Database(dbPath, {
      readonly: true,
      fileMustExist: true
    });

    await source.backup(snapshotPath);
    source.close();

    const data = fs.readFileSync(snapshotPath);

    await pool.query(
      `INSERT INTO in2u_sqlite_snapshot
         (id, data, updated_at)
       VALUES (1, $1, NOW())
       ON CONFLICT (id)
       DO UPDATE SET
         data = EXCLUDED.data,
         updated_at = NOW()`,
      [data]
    );

    console.log(
      'In2U SQLite snapshot saved to Postgres.'
    );
  } catch (error) {
    console.error(
      'Postgres snapshot error:',
      error.message
    );
  } finally {
    try {
      fs.rmSync(snapshotPath, { force: true });
    } catch {}
  }
}

await prepareStore();

const child = spawn(
  process.execPath,
  ['server.js'],
  {
    stdio: 'inherit',
    env: process.env
  }
);

let shuttingDown = false;

const shutdown = async signal => {
  if (shuttingDown) return;

  shuttingDown = true;

  console.log(
    `In2U persistence wrapper received ${signal}.`
  );

  await saveSnapshot();

  try {
    child.kill('SIGTERM');
  } catch {}

  try {
    await pool?.end();
  } catch {}

  process.exit(0);
};

process.on(
  'SIGTERM',
  () => shutdown('SIGTERM')
);

process.on(
  'SIGINT',
  () => shutdown('SIGINT')
);

child.on('exit', async code => {
  if (!shuttingDown) {
    await saveSnapshot();
  }

  try {
    await pool?.end();
  } catch {}

  process.exit(code ?? 0);
});

if (pool) {
  setTimeout(
    () => saveSnapshot().catch(() => {}),
    5000
  );

  setInterval(
    () => saveSnapshot().catch(() => {}),
    15000
  );
                   }
