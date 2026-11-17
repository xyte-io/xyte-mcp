#!/usr/bin/env node
/**
 * Full loop of the partner coupon flows through the built server over stdio.
 *
 *   XYTE_HUB_URL=http://localhost:3000 XYTE_PARTNER_API_KEY=<key> \
 *   XYTE_LOOP_CUSTOMERS='Org A,Org B,Org C,Org D,Org E' npm run loop:partner-coupons
 *
 * WRITES: it creates, changes and deletes coupons and tags, so it refuses to start
 * without an explicit XYTE_HUB_URL and never runs against production. Every name it
 * creates carries a run id, so runs do not collide. See README "Partner coupon loop".
 */

import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { URL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const ROOT = path.resolve(import.meta.dirname, '..');
const ENTRY = path.join(ROOT, 'dist', 'index.js');
const PRODUCTION_HOST = 'hub.xyte.io';
const ALL_FLOWS = ['1', '2', '3', '4', '5', '6', '10', '7', '8', '11', 'isolation', 'gates', 'readonly'];

function fail(message) {
  process.stderr.write(`partner coupon loop: ${message}\n`);
  process.exit(1);
}

const env = process.env;
const hubUrl = env.XYTE_HUB_URL?.trim();
if (!hubUrl) fail('set XYTE_HUB_URL to the hub to test; this loop writes, so it never uses the default.');
if (new URL(hubUrl).hostname === PRODUCTION_HOST) fail('refusing to run against production.');
const key = env.XYTE_PARTNER_API_KEY?.trim();
if (!key) fail('set XYTE_PARTNER_API_KEY to the partner key under test.');
if (!existsSync(ENTRY)) fail(`not built; run npm run build (missing ${ENTRY}).`);
const customers = (env.XYTE_LOOP_CUSTOMERS ?? '').split(',').map((name) => name.trim()).filter(Boolean);
if (customers.length !== 5) fail('set XYTE_LOOP_CUSTOMERS to five customer names, comma separated.');

const runId = env.XYTE_LOOP_RUN_ID ?? Date.now().toString(36);
const flows = env.XYTE_LOOP_FLOWS ? env.XYTE_LOOP_FLOWS.split(',') : ALL_FLOWS;
const NAME = {
  wholeStore: `Loop ${runId} whole store 10%`,
  listing: `Loop ${runId} listing 25 off`,
  code: `Loop ${runId} code 30%`,
  gold: `Loop ${runId} Gold 20%`,
  silverTag: `Loop ${runId} Silver`,
  goldTag: `Loop ${runId} Gold`,
  codeValue: `LOOP-${runId}-30`.toUpperCase()
};

const results = [];

function check(name, pass, detail = '') {
  results.push({ name, pass });
  console.log(`${pass ? ' PASS ' : ' FAIL '} ${name}${detail ? `  (${detail})` : ''}`);
  return pass;
}

function skip(name, why) {
  console.log(` SKIP ${name}  (${why})`);
}

async function startMcpServerClient(partnerApiKey, extraEnv = {}) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [ENTRY],
    env: { PATH: env.PATH ?? '', XYTE_HUB_URL: hubUrl, XYTE_PARTNER_API_KEY: partnerApiKey, ...extraEnv },
    stderr: 'pipe'
  });
  const stderr = [];
  transport.stderr?.on('data', (chunk) => stderr.push(String(chunk)));
  const client = new Client({ name: 'xyte-mcp-partner-coupon-loop', version: '0' });
  await client.connect(transport);
  const server = { client, stderr, call, writes: 0 };

  async function call(endpointKey, args = {}) {
    const isWrite = !endpointKey.split('.').pop().startsWith('get');
    const result = await client.callTool({ name: 'xyte_api_call', arguments: { key: endpointKey, ...args } });
    const text = result.content?.[0]?.text ?? '';
    const status = result.isError ? Number(/failed: (\d{3})/.exec(text)?.[1] ?? 0) : result.structuredContent?.status;
    if (isWrite && status) server.writes += 1;
    return { ok: !result.isError, status, data: result.structuredContent?.data, text };
  }

  return server;
}

const rows = (response) => response.data?.data ?? [];

async function findCoupon(call, name) {
  return rows(await call('partner.coupons.getCoupons')).find((coupon) => coupon.name === name);
}

async function organizationsByName(call) {
  const byName = new Map();
  for (const organization of rows(await call('partner.organizations.getOrganizations'))) {
    byName.set(organization.name, organization);
  }
  return byName;
}

async function tagId(call, name) {
  return rows(await call('partner.organizationTags.getOrganizationTags')).find((tag) => tag.name === name)?.id;
}

async function main() {
  console.log(`partner coupon loop — run ${runId} against ${hubUrl}\n`);
  const partnerServer = await startMcpServerClient(key);
  const { call } = partnerServer;
  const organizations = await organizationsByName(call);
  const targets = customers.map((name) => organizations.get(name));
  if (targets.some((organization) => !organization)) fail(`not every customer was found: ${customers.join(', ')}`);
  const hidden = env.XYTE_LOOP_HIDDEN_CUSTOMER ? organizations.get(env.XYTE_LOOP_HIDDEN_CUSTOMER) : undefined;
  const run = (flow) => flows.includes(flow);

  try {
    if (run('1')) {
      const silver = await call('partner.organizationTags.addOrganizationTag', {
        path: { organization_id: targets[4].id }, body: { name: NAME.silverTag }
      });
      const silverId = silver.data?.id;
      // Detach right away: Silver only exists so flows 1–2 have a tag to target.
      await call('partner.organizationTags.removeOrganizationTag', {
        path: { organization_id: targets[4].id, tag_id: silverId }, confirm: 'partner.organizationTags.removeOrganizationTag'
      });
      const created = await call('partner.coupons.createCoupon', {
        body: { name: NAME.wholeStore, discount_type: 'percent', percent_off: 10, organization_tag_id: silverId }
      });
      check('flow 1: percent coupon for the whole store', created.ok && created.data.percent_off === 10 && created.data.store_listing === null,
        created.ok ? `status ${created.data.status}` : created.text);
    }

    if (run('2')) {
      const listings = rows(await call('partner.storeListings.getStoreListings'));
      const listing = listings.find((row) => row.name === env.XYTE_LOOP_LISTING) ?? listings[0];
      const silverId = await tagId(call, NAME.silverTag);
      const created = await call('partner.coupons.createCoupon', {
        body: { name: NAME.listing, discount_type: 'fixed_amount', amount_off: 25, currency: 'USD', store_listing_id: listing?.id, organization_tag_id: silverId }
      });
      check('flow 2: fixed amount coupon for one store listing', created.ok && created.data.amount_off === 25 && created.data.store_listing?.id === listing?.id,
        created.ok ? `${listings.length} listings, used "${listing?.name}"` : created.text);
    }

    if (run('3')) {
      const created = await call('partner.coupons.createCoupon', {
        body: { name: NAME.code, discount_type: 'percent', percent_off: 30, code: NAME.codeValue }
      });
      check('flow 3: coupon with a code', created.ok && created.data.code === NAME.codeValue,
        created.ok ? `code ${NAME.codeValue}; redeem it in the organization portal` : created.text);
    }

    if (run('4')) {
      const body = { name: NAME.gold, discount_type: 'percent', percent_off: 20 };
      const tagged = [];
      for (const organization of targets) {
        tagged.push(await call('partner.organizationTags.addOrganizationTag', {
          path: { organization_id: organization.id }, body: { name: NAME.goldTag }
        }));
      }
      const goldId = tagged[0].data?.id;
      const first = await call('partner.coupons.createCoupon', { body: { ...body, organization_tag_id: goldId } });
      const again = await call('partner.coupons.createCoupon', { body: { ...body, organization_tag_id: goldId } });
      const retag = await call('partner.organizationTags.addOrganizationTag', {
        path: { organization_id: targets[0].id }, body: { name: NAME.goldTag }
      });
      if (hidden) {
        await call('partner.organizationTags.addOrganizationTag', { path: { organization_id: hidden.id }, body: { name: NAME.goldTag } });
      }
      check('flow 4: tag coupon attached to five customers', first.ok && tagged.every((response) => response.ok && response.data.id === goldId),
        first.ok ? `tag ${goldId}` : first.text);
      const goldCoupons = rows(await call('partner.coupons.getCoupons')).filter((coupon) => coupon.name === NAME.gold);
      check('repeat-safe: create coupon twice leaves one coupon', again.ok && again.data.id === first.data?.id && goldCoupons.length === 1);
      const goldRows = rows(await call('partner.organizations.getOrganizations', { query: { tag: NAME.goldTag } }));
      check('repeat-safe: attach tag twice leaves one tag link', retag.ok && goldRows.filter((row) => row.id === targets[0].id).length === 1
        && retag.data.coupons.some((coupon) => coupon.id === first.data?.id));
    }

    if (run('5')) {
      const goldRows = rows(await call('partner.organizations.getOrganizations', { query: { tag: NAME.goldTag } }));
      const coupon = await findCoupon(call, NAME.gold);
      const visible = targets.every((target) => {
        const row = goldRows.find((row) => row.id === target.id);
        return row?.store_visible === true && row.coupons.some((rowCoupon) => rowCoupon.id === coupon?.id && rowCoupon.source === 'tag');
      });
      const hiddenRow = hidden && goldRows.find((row) => row.id === hidden.id);
      check('flow 5: organizations by tag show the coupon and store_visible', visible && (!hidden || hiddenRow?.store_visible === false),
        `${goldRows.length} tagged${hidden ? `, ${hidden.name} store_visible=${hiddenRow?.store_visible}` : ''}`);
    }

    if (run('6')) {
      const coupon = await findCoupon(call, NAME.gold);
      const endsAt = new Date(Date.now() + 30 * 86_400_000).toISOString();
      const updated = await call('partner.coupons.updateCoupon', { path: { id: coupon?.id }, body: { percent_off: 25, ends_at: endsAt } });
      check('flow 6: change discount and dates', updated.ok && updated.data.percent_off === 25 && updated.data.ends_at != null && updated.data.status === 'active',
        updated.ok ? `ends_at ${updated.data.ends_at}` : updated.text);
    }

    if (run('10')) {
      const goldId = await tagId(call, NAME.goldTag);
      const coupon = await findCoupon(call, NAME.gold);
      const removed = await call('partner.organizationTags.removeOrganizationTag', {
        path: { organization_id: targets[4].id, tag_id: goldId }, confirm: 'partner.organizationTags.removeOrganizationTag'
      });
      const goldRows = rows(await call('partner.organizations.getOrganizations', { query: { tag: NAME.goldTag } }));
      const kept = targets.slice(0, 4).every((target) => goldRows.some((row) => row.id === target.id));
      check('flow 10: remove a tag from one customer, the others keep it',
        removed.ok && removed.data.coupons_removed.some((removedCoupon) => removedCoupon.id === coupon?.id) && kept && !goldRows.some((row) => row.id === targets[4].id),
        removed.ok ? `coupons_removed ${removed.data.coupons_removed.map((coupon) => coupon.name).join(', ')}` : removed.text);
      const again = await call('partner.organizationTags.removeOrganizationTag', {
        path: { organization_id: targets[4].id, tag_id: goldId }, confirm: 'partner.organizationTags.removeOrganizationTag'
      });
      check('flow 10: removing an unattached tag is 404', again.status === 404);
    }

    if (run('7')) {
      const coupon = await findCoupon(call, NAME.gold);
      const updated = await call('partner.coupons.updateCoupon', { path: { id: coupon?.id }, body: { active: false } });
      check('flow 7: deactivate a coupon', updated.ok && updated.data.status === 'inactive', updated.ok ? '' : updated.text);
    }

    if (run('8')) {
      const coupon = await findCoupon(call, NAME.wholeStore);
      const deleted = await call('partner.coupons.deleteCoupon', { path: { id: coupon?.id }, confirm: 'partner.coupons.deleteCoupon' });
      check('flow 8: delete an unused coupon', deleted.ok && deleted.data === null && !(await findCoupon(call, NAME.wholeStore)),
        deleted.ok ? `status ${deleted.status}` : deleted.text);
      const usedId = env.XYTE_LOOP_USED_COUPON_ID;
      if (usedId) {
        const refused = await call('partner.coupons.deleteCoupon', { path: { id: usedId }, confirm: 'partner.coupons.deleteCoupon' });
        check('flow 8: deleting a coupon used in an order is refused', refused.status === 403 && refused.text.includes('Deactivate the coupon instead'),
          refused.text.split('\n')[0]);
      } else skip('flow 8: delete a used coupon', 'set XYTE_LOOP_USED_COUPON_ID');
    }

    if (run('11')) {
      const coupons = rows(await call('partner.coupons.getCoupons'));
      const tags = rows(await call('partner.organizationTags.getOrganizationTags'));
      const gold = tags.find((tag) => tag.name === NAME.goldTag);
      const goldCoupon = coupons.find((coupon) => coupon.name === NAME.gold);
      check('flow 11: list coupons and tags with status and counts',
        goldCoupon?.status === 'inactive' && gold?.organizations_count === 4 + (hidden ? 1 : 0)
          && gold.coupons.some((coupon) => coupon.id === goldCoupon.id && coupon.status === 'inactive'),
        `${coupons.length} coupons, ${tags.length} tags; ${NAME.goldTag}: ${gold?.organizations_count} organizations`);
      for (const coupon of coupons.filter((coupon) => coupon.name.startsWith(`Loop ${runId}`))) console.log(`        coupon "${coupon.name}" ${coupon.status}`);
      for (const tag of tags.filter((tag) => tag.name.startsWith(`Loop ${runId}`))) console.log(`        tag "${tag.name}" organizations=${tag.organizations_count}`);
    }

    if (run('isolation')) await isolation(call, targets[0]);
    if (run('gates')) await gates();
    if (run('readonly')) await readOnly();
  } finally {
    await partnerServer.client.close();
  }

  const stderr = partnerServer.stderr.join('');
  const writeLines = stderr.split('\n').filter((line) => line.includes('] write '));
  check('write log: one line per write that reached the API', writeLines.length === partnerServer.writes, `${writeLines.length} lines, ${partnerServer.writes} writes`);
  check('write log: no key and no body', !stderr.includes(key) && !stderr.includes(NAME.goldTag) && !stderr.includes(NAME.codeValue));

  const failed = results.filter((result) => !result.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) {
    console.log(`\nFailed: ${failed.map((result) => result.name).join(', ')}`);
    process.exitCode = 1;
  }
}

async function isolation(call, customer) {
  const otherKey = env.XYTE_LOOP_OTHER_PARTNER_KEY;
  if (!otherKey) return skip('isolation', 'set XYTE_LOOP_OTHER_PARTNER_KEY');
  const coupon = await findCoupon(call, NAME.gold) ?? await findCoupon(call, NAME.code);
  const goldId = await tagId(call, NAME.goldTag);
  const listings = rows(await call('partner.storeListings.getStoreListings')).map((listing) => listing.id);
  const other = await startMcpServerClient(otherKey);
  try {
    const sees = [
      rows(await other.call('partner.organizations.getOrganizations')).some((row) => row.id === customer.id),
      rows(await other.call('partner.coupons.getCoupons')).some((row) => row.id === coupon?.id),
      rows(await other.call('partner.organizationTags.getOrganizationTags')).some((row) => row.id === goldId),
      rows(await other.call('partner.storeListings.getStoreListings')).some((row) => listings.includes(row.id))
    ];
    check('isolation: another partner reads none of the organizations, coupons, tags or listings', !sees.some(Boolean), `seen: ${sees}`);
    const statuses = [
      (await other.call('partner.coupons.updateCoupon', { path: { id: coupon?.id }, body: { name: 'hijack' } })).status,
      (await other.call('partner.coupons.deleteCoupon', { path: { id: coupon?.id }, confirm: 'partner.coupons.deleteCoupon' })).status,
      (await other.call('partner.organizationTags.addOrganizationTag', { path: { organization_id: customer.id }, body: { name: 'hijack' } })).status,
      (await other.call('partner.organizationTags.removeOrganizationTag', {
        path: { organization_id: customer.id, tag_id: goldId }, confirm: 'partner.organizationTags.removeOrganizationTag'
      })).status,
      (await other.call('partner.coupons.createCoupon', {
        body: { name: 'hijack', discount_type: 'percent', percent_off: 50, organization_tag_id: goldId }
      })).status
    ];
    check('isolation: another partner changes none of them', statuses.slice(0, 4).every((status) => status === 404) && [404, 422].includes(statuses[4]),
      `update/delete/add tag/remove tag/create on foreign tag: ${statuses.join('/')}`);
  } finally {
    await other.client.close();
  }
}

async function gates() {
  const gatedKey = env.XYTE_LOOP_NO_COUPONS_PARTNER_KEY;
  if (!gatedKey) return skip('gates', 'set XYTE_LOOP_NO_COUPONS_PARTNER_KEY (store coupons off)');
  const gated = await startMcpServerClient(gatedKey);
  try {
    const couponStatuses = [
      (await gated.call('partner.coupons.getCoupons')).status,
      (await gated.call('partner.coupons.createCoupon', { body: { name: 'gated', discount_type: 'percent', percent_off: 5, code: `GATED-${runId}` } })).status
    ];
    check('gates: coupon calls return 403 without store coupons', couponStatuses.every((status) => status === 403), couponStatuses.join('/'));
    const organization = rows(await gated.call('partner.organizations.getOrganizations'))[0];
    const tag = organization && await gated.call('partner.organizationTags.addOrganizationTag', {
      path: { organization_id: organization.id }, body: { name: `Loop ${runId} gated` }
    });
    const list = await gated.call('partner.organizationTags.getOrganizationTags');
    const removed = tag?.ok && await gated.call('partner.organizationTags.removeOrganizationTag', {
      path: { organization_id: organization.id, tag_id: tag.data.id }, confirm: 'partner.organizationTags.removeOrganizationTag'
    });
    check('gates: tag calls still work', Boolean(tag?.ok && list.ok && removed?.ok), organization ? '' : 'the partner has no organization');
  } finally {
    await gated.client.close();
  }
}

async function readOnly() {
  const readOnlyServer = await startMcpServerClient(key, { XYTE_MCP_READ_ONLY: '1' });
  try {
    const reads = ['partner.organizations.getOrganizations', 'partner.organizationTags.getOrganizationTags', 'partner.coupons.getCoupons', 'partner.storeListings.getStoreListings'];
    const readResults = await Promise.all(reads.map((endpointKey) => readOnlyServer.call(endpointKey)));
    check('read-only: reads work', readResults.every((response) => response.ok));
    const refusals = [
      await readOnlyServer.call('partner.coupons.createCoupon', { body: { name: 'ro', discount_type: 'percent', percent_off: 5, code: `RO-${runId}` } }),
      await readOnlyServer.call('partner.coupons.updateCoupon', { path: { id: 'x' }, body: { name: 'ro' } }),
      await readOnlyServer.call('partner.coupons.deleteCoupon', { path: { id: 'x' }, confirm: 'partner.coupons.deleteCoupon' }),
      await readOnlyServer.call('partner.organizationTags.addOrganizationTag', { path: { organization_id: 'x' }, body: { name: 'ro' } }),
      await readOnlyServer.call('partner.organizationTags.removeOrganizationTag', {
        path: { organization_id: 'x', tag_id: 'x' }, confirm: 'partner.organizationTags.removeOrganizationTag'
      })
    ];
    check('read-only: every write is refused', refusals.every((refusal) => !refusal.ok && refusal.text.includes('read-only')));
    check('read-only: nothing in the write log', !readOnlyServer.stderr.join('').includes('] write '));
  } finally {
    await readOnlyServer.client.close();
  }
}

main().catch((error) => {
  console.error(`\npartner coupon loop failed: ${error.stack ?? error.message}`);
  process.exit(1);
});
