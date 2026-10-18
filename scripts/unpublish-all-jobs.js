/**
 * Unpublish (or restore) job listings without deleting anything.
 *
 *   node scripts/unpublish-all-jobs.js                 -> dry run: lists the active jobs, changes nothing
 *   node scripts/unpublish-all-jobs.js --apply         -> sets every active job to 'inactive' and saves a backup list
 *   node scripts/unpublish-all-jobs.js --restore=ID1,ID2 -> sets just those job ids back to 'active'
 *
 * Needs MONGODB_URI in the environment (or a local .env file). The public site only shows
 * jobs whose status is 'active', so 'inactive' jobs disappear from the site and from direct links.
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const apply = process.argv.includes('--apply');
const restoreArg = process.argv.find(a => a.startsWith('--restore='));
const restoreIds = restoreArg ? restoreArg.split('=')[1].split(',').map(s => s.trim()).filter(Boolean) : [];

if (!process.env.MONGODB_URI) {
  console.error('MONGODB_URI is not set. Set it (or add it to .env) and run again.');
  process.exit(1);
}

const Job = mongoose.model('Job', new mongoose.Schema({ id: String, title: String, location: String, status: String }, { strict: false }));

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  try {
    if (restoreIds.length) {
      const res = await Job.updateMany({ id: { $in: restoreIds } }, { $set: { status: 'active' } });
      console.log(`Restored ${res.modifiedCount} of ${restoreIds.length} job(s) to active.`);
      return;
    }
    const active = await Job.find({ status: 'active' }).select('id title location').lean();
    console.log(`${active.length} active job(s):`);
    active.forEach(j => console.log(`  ${j.id}  ${j.title} (${j.location || 'no location'})`));
    if (!apply) { console.log('\nDry run only. Re-run with --apply to unpublish them.'); return; }
    const backup = path.join(__dirname, `unpublished-jobs-${new Date().toISOString().slice(0, 10)}.json`);
    fs.writeFileSync(backup, JSON.stringify(active, null, 2));
    const res = await Job.updateMany({ status: 'active' }, { $set: { status: 'inactive' } });
    console.log(`\nUnpublished ${res.modifiedCount} job(s). Backup of their ids: ${backup}`);
    console.log('Restore any of them with: node scripts/unpublish-all-jobs.js --restore=ID1,ID2');
  } finally {
    await mongoose.disconnect();
  }
})().catch(e => { console.error(e.message); process.exit(1); });
