#!/usr/bin/env node
/**
 * Full loop of the partner store reads through the built server over stdio:
 * store settings, products, store listings, orders, payments, subscriptions and
 * sold products, followed from a coupon to its order and everything hanging off it.
 *
 *   XYTE_HUB_URL=http://localhost:3000 XYTE_PARTNER_API_KEY=<key> npm run loop:partner-store-reads
 *
 * Read-only unless XYTE_LOOP_APPROVE_ORDER_ID is set: then it approves that order,
 * which cannot be undone. It refuses to start without an explicit XYTE_HUB_URL and
 * refuses hub.xyte.io. See README "Partner store reads loop".
 */

import { rows, startLoop } from './loop-common.mjs';

const { env, hubUrl, key, print, printed, check, skip, finish, checkWriteLog, startMcpServerClient } = startLoop('partner store reads loop');

const firstLine = (response) => response.text.split('\n')[0];
const detail = (response, okDetail = '') => (response.ok ? okDetail : firstLine(response));

async function reads(call) {
  const settings = await call('partner.storeSettings.getStoreSettings');
  check('store settings', settings.ok, detail(settings, `currencies ${settings.data?.currencies}`));

  for (const [name, listKey, getKey, idParam] of [
    ['products', 'partner.products.getProducts', 'partner.products.getProduct', 'product_id'],
    ['store listings', 'partner.storeListings.getStoreListings', 'partner.storeListings.getStoreListing', 'store_listing_id']
  ]) {
    const list = await call(listKey);
    check(`${name}: list`, list.ok, detail(list, `${rows(list).length} rows`));
    const first = rows(list)[0];
    if (!first) {
      skip(`${name}: get the first one`, `no ${name}`);
      continue;
    }
    const one = await call(getKey, { path: { [idParam]: first.id } });
    check(`${name}: get the first one`, one.ok && one.data.id === first.id, detail(one));
  }

  for (const [name, listKey] of [
    ['orders', 'partner.orders.getOrders'],
    ['payments', 'partner.payments.getPayments'],
    ['subscriptions', 'partner.subscriptions.getSubscriptions'],
    ['sold products', 'partner.soldProducts.getSoldProducts']
  ]) {
    const list = await call(listKey);
    check(`${name}: list`, list.ok, detail(list, `${rows(list).length} rows`));
  }
}

const LINKS = [
  'chain: orders filtered by the coupon',
  'chain: an order item carries the coupon',
  'chain: the payment lists the order',
  'chain: the subscription of the order and its invoice items',
  'chain: a sold product of the order'
];

// A missing link skips itself and every later link.
function skipFrom(link, why) {
  for (const name of LINKS.slice(LINKS.indexOf(link))) skip(name, why);
}

async function chain(call) {
  const couponId = env.XYTE_LOOP_COUPON_ID
    ?? rows(await call('partner.coupons.getCoupons')).find((coupon) => coupon.used_in_orders === true)?.id;
  if (!couponId) return skipFrom(LINKS[0], 'no coupon used in an order; set XYTE_LOOP_COUPON_ID');

  const orders = await call('partner.orders.getOrders', { query: { coupon_id: couponId } });
  if (!check(LINKS[0], orders.ok && rows(orders).length > 0, detail(orders, `${rows(orders).length} orders`))) {
    return skipFrom(LINKS[1], 'no order for the coupon');
  }

  // Prefer the order that reaches every later link: a payment and a subscription item.
  const details = [];
  for (const row of rows(orders)) {
    const one = await call('partner.orders.getOrder', { path: { order_id: row.id } });
    if (one.ok) details.push(one.data);
  }
  const score = (order) => (order.payment ? 2 : 0) + (order.items.some((item) => item.subscription_id) ? 1 : 0);
  const order = details.sort((a, b) => score(b) - score(a))[0];
  if (!check(LINKS[1], order?.items.some((item) => item.coupon?.id === couponId), order ? `order ${order.short_id}` : 'no order could be read')) {
    return skipFrom(LINKS[2], 'no order with the coupon');
  }

  if (!order.payment) return skipFrom(LINKS[2], 'the order has no payment');
  // Get Payment answers 404 for a payment made outside the store.
  if (order.payment_method === 'offline') return skipFrom(LINKS[2], 'the order was paid offline');
  const payment = await call('partner.payments.getPayment', { path: { payment_id: order.payment.id } });
  if (!check(LINKS[2], payment.ok && payment.data.order_ids.includes(order.id), detail(payment))) {
    return skipFrom(LINKS[3], 'the payment does not list the order');
  }

  const subscriptionId = order.items.find((item) => item.subscription_id)?.subscription_id;
  if (!subscriptionId) return skipFrom(LINKS[3], 'no order item has a subscription');
  const subscription = await call('partner.subscriptions.getSubscription', { path: { subscription_id: subscriptionId } });
  const invoiceItems = await call('partner.subscriptions.getSubscriptionInvoiceItems', { path: { subscription_id: subscriptionId } });
  if (!check(LINKS[3], subscription.ok && subscription.data.order_id === order.id && invoiceItems.ok,
    subscription.ok ? detail(invoiceItems, `${rows(invoiceItems).length} invoice items`) : firstLine(subscription))) {
    return skipFrom(LINKS[4], 'the subscription does not match the order');
  }

  const soldProduct = rows(await call('partner.soldProducts.getSoldProducts', { query: { order_id: order.id } }))[0];
  if (!soldProduct) return skipFrom(LINKS[4], 'no sold product for the order');
  const one = await call('partner.soldProducts.getSoldProduct', { path: { sold_product_id: soldProduct.id } });
  check(LINKS[4], one.ok && one.data.order_id === order.id, detail(one));
}

async function timeFilter(call) {
  // Passed plain: the server URL-encodes "+" as %2B once.
  const withOffset = await call('partner.orders.getOrders', { query: { created_from: '2000-01-01T02:00:00+02:00' } });
  check('time filter: a "+02:00" offset passed plain is accepted', withOffset.status === 200, detail(withOffset, `status ${withOffset.status}`));
  const noOffset = await call('partner.orders.getOrders', { query: { created_from: '2000-01-01T00:00:00' } });
  check('time filter: a time without an offset is 422', noOffset.status === 422, `status ${noOffset.status}`);
}

async function approve(call) {
  const orderId = env.XYTE_LOOP_APPROVE_ORDER_ID;
  if (!orderId) return skip('approve order', 'set XYTE_LOOP_APPROVE_ORDER_ID to an order waiting for approval');
  const first = await call('partner.orders.approveOrder', { path: { order_id: orderId } });
  check('approve: the order is approved', first.ok && first.data.approval_state === 'approved', detail(first));
  const again = await call('partner.orders.approveOrder', { path: { order_id: orderId } });
  check('approve: approving again is ok and changes nothing', again.ok && again.data.approval_state === 'approved', detail(again));
}

async function readOnly() {
  const readOnlyServer = await startMcpServerClient(key, { XYTE_MCP_READ_ONLY: '1' });
  try {
    const reads = ['partner.storeSettings.getStoreSettings', 'partner.products.getProducts', 'partner.orders.getOrders', 'partner.payments.getPayments'];
    const readResults = await Promise.all(reads.map((endpointKey) => readOnlyServer.call(endpointKey)));
    check('read-only: reads work', readResults.every((response) => response.ok));
    const refused = await readOnlyServer.call('partner.orders.approveOrder', { path: { order_id: 'x' } });
    check('read-only: approving an order is refused', !refused.ok && refused.text.includes('read-only'), firstLine(refused));
  } finally {
    await readOnlyServer.client.close();
  }
}

async function main() {
  print(`partner store reads loop against ${hubUrl}\n`);
  const partnerServer = await startMcpServerClient(key);
  try {
    await reads(partnerServer.call);
    await chain(partnerServer.call);
    await timeFilter(partnerServer.call);
    await approve(partnerServer.call);
  } finally {
    await partnerServer.client.close();
  }
  await readOnly();

  const stderr = checkWriteLog();
  check('no key in any server log or in this output', !stderr.includes(key) && !printed.some((line) => line.includes(key)));
  finish();
}

main().catch((error) => {
  console.error(`\npartner store reads loop failed: ${error.stack ?? error.message}`);
  process.exit(1);
});
