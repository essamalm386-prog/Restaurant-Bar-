/* =========================================================================
   JARABA — Worker unique : serveur de liaison + tunnel de vente autonome
   -------------------------------------------------------------------------
   Déploiement : ce fichier remplace worker.js dans le dépôt GitHub connecté
   à Cloudflare. Le binding KV « SALONS » sert aux deux usages, avec des
   préfixes de clés distincts (liaison éphémère / ventes durables).

   Secrets à définir dans le Worker (Settings → Variables → Encrypt) :
     LIC_SEL        le sel qui fabrique les licences
     CINETPAY_KEY   apikey CinetPay
     CINETPAY_SITE  site_id CinetPay
     ADMIN_CLE      mot de passe de votre tableau de bord
     SITE_VENTE     adresse de la page de vente (pour les retours de paiement)
   ========================================================================= */

const RETENTION = 10800;            /* liaison : 3 h */
const CP_API    = 'https://api-checkout.cinetpay.com/v2';

/* ---- Catalogue commercial : modifiable sans toucher au reste ------------ */
const FORMULES = {
  m1:  { mois: 1,  prix: 5000,  titre: '1 mois' },
  m6:  { mois: 6,  prix: 25000, titre: '6 mois' },
  m12: { mois: 12, prix: 40000, titre: '12 mois' }
};
const DEVISE = 'XAF';
const BONUS_FILLEUL = 1;            /* mois offerts à celui qui utilise un code */
const BONUS_PARRAIN  = 1;            /* mois offerts à celui qui l'a donné */

/* ------------------------------------------------------------------ */
/*  Utilitaires                                                        */
/* ------------------------------------------------------------------ */
const cors = () => ({
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json; charset=utf-8'
});
const json = (code, obj) => new Response(JSON.stringify(obj), { status: code, headers: cors() });
const html = (code, s) => new Response(s, {
  status: code,
  headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
});

/* Reproduit EXACTEMENT le hachage du générateur de licences.
   La multiplication dépasse volontairement 2^53 : ne pas « corriger »
   en Math.imul, sinon les clés produites ne seraient plus reconnues. */
function hashStr(str) {
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 = (h1 ^ c) >>> 0; h1 = (h1 * 0x01000193) >>> 0;
    h2 = ((h2 << 5) + h2 + c) >>> 0;
  }
  return h1.toString(16).toUpperCase().padStart(8, '0')
       + h2.toString(16).toUpperCase().padStart(8, '0');
}
function b64enc(str) {
  const o = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < o.length; i++) bin += String.fromCharCode(o[i]);
  return btoa(bin).replace(/=+$/, '');
}
/* Une licence court jusqu'à la FIN d'un mois : c'est la granularité du format. */
function moisPlus(n) {
  const d = new Date();
  d.setMonth(d.getMonth() + n);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
}
function fabriquerCle(sel, client, exp) {
  const sig = hashStr(sel + '|' + client.toUpperCase() + '|' + exp).slice(0, 10);
  return 'BARLIC.' + b64enc(JSON.stringify([client, exp, sig]));
}
const nettoyerTel = t => String(t || '').replace(/[^\d+]/g, '').slice(0, 20);
const nettoyerNom = n => String(n || '').trim().replace(/[<>|]/g, '').slice(0, 60);
const ref = () => 'JRB' + Date.now().toString(36).toUpperCase()
                 + Math.random().toString(36).slice(2, 6).toUpperCase();
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const fmtF = n => Number(n || 0).toLocaleString('fr-FR').replace(/ | /g, ' ') + ' F';

/* ---- Parrainage ---------------------------------------------------
   Le code est tiré du numéro : toujours le même pour un client donné,
   sans rien stocker de plus. Alphabet sans 0/O/1/I, dictable au téléphone. */
const ALPHA_CODE = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
/* Hachage propre — surtout pas celui des licences, dont les bits de poids
   faible sont dégradés par la multiplication qui déborde volontairement. */
function hash32(str, graine) {
  let h = graine >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  h ^= h >>> 16; h = Math.imul(h, 0x7feb352d) >>> 0;
  h ^= h >>> 15; h = Math.imul(h, 0x846ca68b) >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
}
function codeParrain(tel, variante) {
  const sel = 'parrain|' + tel + (variante ? '|' + variante : '');
  let a = hash32(sel, 0x811c9dc5), b = hash32(sel, 0x9e3779b9), s = '';
  for (let i = 0; i < 3; i++) { s += ALPHA_CODE[a & 31]; a >>>= 5; }
  for (let i = 0; i < 3; i++) { s += ALPHA_CODE[b & 31]; b >>>= 5; }
  return s;
}
/* Attribue le code, en écartant la collision improbable avec un autre numéro. */
async function attribuerCode(env, tel) {
  for (let v = 0; v < 12; v++) {
    const c = codeParrain(tel, v);
    const pris = await env.SALONS.get('v:parr:' + c);
    if (!pris) { await env.SALONS.put('v:parr:' + c, tel); return c; }
    if (pris === tel) return c;
  }
  return codeParrain(tel, Date.now());   /* filet, jamais atteint en pratique */
}
/* Ajoute des mois à une échéance 'AAAA-MM', sans jamais raccourcir. */
function prolonger(exp, mois) {
  const [a, m] = String(exp).split('-').map(Number);
  const d = new Date(Date.UTC(a, m - 1, 1));
  d.setUTCMonth(d.getUTCMonth() + mois);
  return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0');
}
/* Récompense le parrain : sa licence gagne des mois, sa nouvelle clé
   l'attend sur la page de parrainage. Il n'a rien à réclamer. */
async function recompenserParrain(env, telParrain, filleul) {
  const brut = await env.SALONS.get('v:tel:' + telParrain);
  if (!brut) return;
  const v = JSON.parse(brut);
  const base = v.exp > moisPlus(0) ? v.exp : moisPlus(0);
  const exp = prolonger(base, BONUS_PARRAIN);
  const maj = { ...v, exp, cle: fabriquerCle(env.LIC_SEL, v.etab, exp) };
  await env.SALONS.put('v:tel:' + telParrain, JSON.stringify(maj));
  const bl = await env.SALONS.get('v:filleuls:' + telParrain);
  const liste = bl ? JSON.parse(bl) : [];
  liste.unshift({ etab: filleul, date: new Date().toISOString(), mois: BONUS_PARRAIN });
  await env.SALONS.put('v:filleuls:' + telParrain, JSON.stringify(liste.slice(0, 200)));
}

/* Index des ventes : une liste légère, suffisante pour un tableau de bord. */
async function ajouterIndex(env, entree) {
  const brut = await env.SALONS.get('v:index');
  const liste = brut ? JSON.parse(brut) : [];
  liste.unshift(entree);
  await env.SALONS.put('v:index', JSON.stringify(liste.slice(0, 2000)));
}

/* ------------------------------------------------------------------ */
/*  Tunnel de vente                                                    */
/* ------------------------------------------------------------------ */

/* Essai gratuit — une seule fois par numéro. Court jusqu'à la fin du mois
   PROCHAIN : tout le monde dispose donc d'au moins trente jours pleins. */
async function essai(req, env) {
  const b = await req.json();
  const etab = nettoyerNom(b.etab);
  const tel  = nettoyerTel(b.tel);
  if (!etab) return json(400, { erreur: "Indiquez le nom de votre établissement." });
  if (tel.length < 8) return json(400, { erreur: 'Indiquez un numéro de téléphone valide.' });

  const deja = await env.SALONS.get('v:essai:' + tel);
  if (deja) {
    const o = JSON.parse(deja);
    return json(200, { cle: o.cle, exp: o.exp, etab: o.etab, rappel: true });
  }
  const exp = moisPlus(2).slice(0, 7);          /* fin du mois prochain */
  const cle = fabriquerCle(env.LIC_SEL, etab, exp);
  const o = { cle, exp, etab, tel, type: 'essai', date: new Date().toISOString() };
  await env.SALONS.put('v:essai:' + tel, JSON.stringify(o));
  await env.SALONS.put('v:tel:' + tel, JSON.stringify(o));
  await ajouterIndex(env, { ref: 'ESSAI', etab, tel, formule: 'Essai', montant: 0, exp, date: o.date });
  return json(200, { cle, exp, etab });
}

/* Lance un paiement CinetPay et renvoie l'adresse de la page de paiement. */
async function acheter(req, env, origine) {
  const b = await req.json();
  const etab = nettoyerNom(b.etab);
  const tel  = nettoyerTel(b.tel);
  const f    = FORMULES[b.formule];
  if (!etab) return json(400, { erreur: "Indiquez le nom de votre établissement." });
  if (tel.length < 8) return json(400, { erreur: 'Indiquez un numéro de téléphone valide.' });
  if (!f) return json(400, { erreur: 'Formule inconnue.' });
  if (!env.CINETPAY_KEY || !env.CINETPAY_SITE)
    return json(503, { erreur: "Le paiement n'est pas encore activé. Contactez-nous par WhatsApp." });

  /* Code de parrainage : validé maintenant, honoré à la livraison. */
  let parrainTel = '';
  const code = String(b.parrain || '').trim().toUpperCase();
  if (code) {
    const t = await env.SALONS.get('v:parr:' + code);
    if (t && t !== tel) parrainTel = t;
  }

  const id = ref();
  const site = env.SITE_VENTE || origine;
  await env.SALONS.put('v:cmd:' + id,
    JSON.stringify({ id, etab, tel, formule: b.formule, mois: f.mois, montant: f.prix,
                     parrainTel, etat: 'attente', date: new Date().toISOString() }),
    { expirationTtl: 86400 * 7 });

  const r = await fetch(CP_API + '/payment', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      apikey: env.CINETPAY_KEY,
      site_id: env.CINETPAY_SITE,
      transaction_id: id,
      amount: f.prix,
      currency: DEVISE,
      description: 'Jaraba — licence ' + f.titre + ' — ' + etab,
      customer_name: etab,
      customer_phone_number: tel,
      channels: 'ALL',
      notify_url: new URL(req.url).origin + '/vente/notify',
      return_url: site.replace(/\/+$/, '') + '/merci.html?ref=' + id,
      metadata: id
    })
  });
  const j = await r.json().catch(() => ({}));
  const url = j && j.data && j.data.payment_url;
  if (!url) return json(502, { erreur: "Le service de paiement n'a pas répondu. Réessayez.",
                               detail: (j && j.description) || '' });
  return json(200, { url, ref: id });
}

/* Webhook CinetPay. La notification n'est JAMAIS crue sur parole :
   le statut est revérifié en direct auprès de CinetPay avant de livrer. */
async function notify(req, env) {
  let id = '';
  try {
    const ct = req.headers.get('content-type') || '';
    if (ct.includes('json')) { const b = await req.json(); id = b.cpm_trans_id || b.transaction_id || ''; }
    else { const f = await req.formData(); id = f.get('cpm_trans_id') || f.get('transaction_id') || ''; }
  } catch (e) { /* corps illisible : on sort proprement */ }
  if (!id) return json(200, { ok: true });

  await livrer(env, String(id));
  return json(200, { ok: true });
}

/* Vérifie auprès de CinetPay puis fabrique et range la licence. Idempotent. */
async function livrer(env, id) {
  const dejaVendu = await env.SALONS.get('v:paye:' + id);
  if (dejaVendu) return JSON.parse(dejaVendu);

  const brut = await env.SALONS.get('v:cmd:' + id);
  if (!brut) return null;
  const cmd = JSON.parse(brut);

  const r = await fetch(CP_API + '/payment/check', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apikey: env.CINETPAY_KEY, site_id: env.CINETPAY_SITE, transaction_id: id })
  });
  const j = await r.json().catch(() => ({}));
  const st = (j && j.data && j.data.status) || (j && j.code) || '';
  if (!(st === 'ACCEPTED' || st === '00' || st === 'SUCCES')) return null;

  const montant = Number((j.data && j.data.amount) || 0);
  if (montant && montant < cmd.montant) return null;       /* montant insuffisant : on ne livre pas */

  /* On repart de ce qui reste, jamais du mois courant : racheter tôt ne doit
     jamais raccourcir une licence en cours. */
  const bonus = cmd.parrainTel ? BONUS_FILLEUL : 0;
  const ancien = await env.SALONS.get('v:tel:' + cmd.tel);
  const courant = moisPlus(0);
  let base = courant;
  if (ancien) {
    const prec = JSON.parse(ancien).exp;
    if (prec && prec > base) base = prec;
  }
  const exp = prolonger(base, cmd.mois + bonus);
  const cle = fabriquerCle(env.LIC_SEL, cmd.etab, exp);
  const code = await attribuerCode(env, cmd.tel);          /* il peut parrainer à son tour */
  const vente = { ref: id, cle, exp, etab: cmd.etab, tel: cmd.tel,
                  formule: cmd.formule, montant: cmd.montant, bonus,
                  code, date: new Date().toISOString() };
  await env.SALONS.put('v:paye:' + id, JSON.stringify(vente));
  await env.SALONS.put('v:tel:' + cmd.tel, JSON.stringify(vente));
  if (cmd.parrainTel) await recompenserParrain(env, cmd.parrainTel, cmd.etab);
  await ajouterIndex(env, { ref: id, etab: cmd.etab, tel: cmd.tel,
                            formule: (FORMULES[cmd.formule] || {}).titre || cmd.formule,
                            montant: cmd.montant, exp, parraine: !!cmd.parrainTel, date: vente.date });
  return vente;
}

/* La page « merci » interroge ceci. Relance la vérification si le webhook
   a pris du retard — le client n'attend donc jamais après CinetPay. */
async function laCle(url, env) {
  const id = url.searchParams.get('ref') || '';
  if (!id) return json(400, { erreur: 'Référence manquante.' });
  let v = await env.SALONS.get('v:paye:' + id);
  if (v) return json(200, JSON.parse(v));
  const livree = await livrer(env, id);
  if (livree) return json(200, livree);
  return json(202, { attente: true });
}

/* Filet de sécurité client : retrouver sa clé avec son numéro. */
async function mesCles(url, env) {
  const tel = nettoyerTel(url.searchParams.get('tel'));
  if (tel.length < 8) return json(400, { erreur: 'Numéro invalide.' });
  const v = await env.SALONS.get('v:tel:' + tel);
  if (!v) return json(404, { erreur: 'Aucune licence trouvée pour ce numéro.' });
  return json(200, JSON.parse(v));
}

/* Espace de parrainage : son code, ses filleuls, et sa clé prolongée. */
async function parrainage(url, env) {
  const tel = nettoyerTel(url.searchParams.get('tel'));
  if (tel.length < 8) return json(400, { erreur: 'Numéro invalide.' });
  const brut = await env.SALONS.get('v:tel:' + tel);
  if (!brut) return json(404, { erreur: "Aucune licence à ce numéro. Le parrainage est réservé aux clients." });
  const v = JSON.parse(brut);
  const code = await attribuerCode(env, tel);
  const bl = await env.SALONS.get('v:filleuls:' + tel);
  const filleuls = bl ? JSON.parse(bl) : [];
  return json(200, {
    code, etab: v.etab, cle: v.cle, exp: v.exp,
    filleuls: filleuls.length,
    moisGagnes: filleuls.reduce((s, f) => s + (f.mois || 0), 0),
    detail: filleuls.slice(0, 20).map(f => ({ etab: f.etab, date: (f.date || '').slice(0, 10) }))
  });
}
/* Vérifie un code avant l'achat, pour rassurer l'acheteur. */
async function verifierCode(url, env) {
  const code = String(url.searchParams.get('code') || '').trim().toUpperCase();
  const t = await env.SALONS.get('v:parr:' + code);
  if (!t) return json(404, { valide: false });
  return json(200, { valide: true, bonus: BONUS_FILLEUL });
}

/* ------------------------------------------------------------------ */
/*  Tableau de bord privé                                              */
/* ------------------------------------------------------------------ */
async function admin(url, env) {
  if (!env.ADMIN_CLE || url.searchParams.get('k') !== env.ADMIN_CLE)
    return html(401, '<meta charset="utf-8"><p style="font-family:sans-serif">Accès refusé.</p>');

  const brut = await env.SALONS.get('v:index');
  const liste = brut ? JSON.parse(brut) : [];
  const moisCourant = new Date().toISOString().slice(0, 7);
  const payantes = liste.filter(v => v.montant > 0);
  const caTotal = payantes.reduce((s, v) => s + v.montant, 0);
  const caMois = payantes.filter(v => (v.date || '').slice(0, 7) === moisCourant)
                         .reduce((s, v) => s + v.montant, 0);
  const bientot = liste.filter(v => v.exp && v.exp <= moisCourant);

  const lignes = liste.slice(0, 300).map(v => '<tr>'
    + '<td>' + esc((v.date || '').slice(0, 10)) + '</td>'
    + '<td><b>' + esc(v.etab) + '</b></td>'
    + '<td>' + esc(v.tel) + '</td>'
    + '<td>' + esc(v.formule) + '</td>'
    + '<td class="n">' + (v.montant ? fmtF(v.montant) : '—') + '</td>'
    + '<td>' + esc(v.exp) + '</td></tr>').join('');

  return html(200, `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jaraba — ventes</title><style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
background:#E8E9EC;color:#1B1C1E;padding:18px}
h1{font-size:24px;font-weight:800;margin:0 0 14px}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.c{background:#fff;border-radius:18px;padding:15px;box-shadow:0 1px 3px rgba(27,28,30,.06)}
.c .v{font-size:24px;font-weight:800;letter-spacing:-.5px}
.c .l{font-size:11px;color:#84878D;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-top:3px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:18px;overflow:hidden;
box-shadow:0 1px 3px rgba(27,28,30,.06);font-size:13.5px}
th{background:#051D38;color:#fff;text-align:left;padding:11px;font-size:11px;
text-transform:uppercase;letter-spacing:.4px}
td{padding:11px;border-bottom:1px solid #F0F1F3}
td.n{text-align:right;font-variant-numeric:tabular-nums;font-weight:700}
.warn{background:#F5EDDE;color:#8E6B2F;border-radius:14px;padding:12px 14px;font-size:13.5px;
font-weight:600;margin-bottom:14px}
</style></head><body>
<h1>Ventes Jaraba</h1>
<div class="k">
  <div class="c"><div class="v">${fmtF(caMois)}</div><div class="l">Ce mois-ci</div></div>
  <div class="c"><div class="v">${fmtF(caTotal)}</div><div class="l">Depuis le début</div></div>
  <div class="c"><div class="v">${payantes.length}</div><div class="l">Licences vendues</div></div>
  <div class="c"><div class="v">${liste.length - payantes.length}</div><div class="l">Essais</div></div>
</div>
${bientot.length ? '<div class="warn">' + bientot.length
  + ' licence(s) arrivent à échéance ce mois-ci — c\'est le moment de relancer.</div>' : ''}
<table><tr><th>Date</th><th>Établissement</th><th>Téléphone</th><th>Formule</th>
<th style="text-align:right">Montant</th><th>Fin</th></tr>${lignes}</table>
</body></html>`);
}

/* ------------------------------------------------------------------ */
/*  Routage                                                            */
/* ------------------------------------------------------------------ */
export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });
    const u = new URL(req.url);
    const chemin = u.pathname.replace(/\/+$/, '') || '/';

    try {
      /* ---------------- tunnel de vente ---------------- */
      if (chemin === '/vente/tarifs' && req.method === 'GET')
        return json(200, { devise: DEVISE, formules: FORMULES });
      if (chemin === '/vente/essai'  && req.method === 'POST') return essai(req, env);
      if (chemin === '/vente/acheter'&& req.method === 'POST') return acheter(req, env, u.origin);
      if (chemin === '/vente/notify' && req.method === 'POST') return notify(req, env);
      if (chemin === '/vente/cle'    && req.method === 'GET')  return laCle(u, env);
      if (chemin === '/vente/mes-cles' && req.method === 'GET') return mesCles(u, env);
      if (chemin === '/vente/parrainage' && req.method === 'GET') return parrainage(u, env);
      if (chemin === '/vente/code' && req.method === 'GET') return verifierCode(u, env);
      if (chemin === '/vente/admin'  && req.method === 'GET')  return admin(u, env);

      /* ---------------- serveur de liaison ------------- */
      if (chemin === '/' || chemin === '/sante') return json(200, { ok: true, service: 'liaison' });

      if (chemin === '/menu' && req.method === 'POST') {
        const b = await req.json();
        if (!b.s || !b.menu) return json(400, { erreur: 'salon ou carte manquant' });
        await env.SALONS.put('menu:' + b.s, JSON.stringify(b.menu), { expirationTtl: 604800 });
        return json(200, { ok: true });
      }
      if (chemin === '/menu' && req.method === 'GET') {
        const m = await env.SALONS.get('menu:' + u.searchParams.get('s'));
        if (!m) return json(404, { erreur: 'carte introuvable' });
        return json(200, { menu: JSON.parse(m) });
      }
      if (chemin === '/commande' && req.method === 'POST') {
        const b = await req.json();
        if (!b.s || !Array.isArray(b.items) || !b.items.length)
          return json(400, { erreur: 'commande vide' });
        const cle = 'cmd:' + b.s;
        const brut = await env.SALONS.get(cle);
        const list = brut ? JSON.parse(brut) : [];
        const c = { id: 'C' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
                    table: String(b.table || '').slice(0, 40), items: b.items.slice(0, 60),
                    ts: Date.now(), pris: false };
        list.push(c);
        await env.SALONS.put(cle, JSON.stringify(list.slice(-200)), { expirationTtl: RETENTION });
        return json(200, { ok: true, id: c.id });
      }
      if (chemin === '/commandes' && req.method === 'GET') {
        const brut = await env.SALONS.get('cmd:' + u.searchParams.get('s'));
        const depuis = Number(u.searchParams.get('depuis')) || 0;
        const list = (brut ? JSON.parse(brut) : []).filter(c => !c.pris && c.ts > depuis);
        return json(200, { t: Date.now(), list });
      }
      if (chemin === '/pris' && req.method === 'POST') {
        const b = await req.json();
        const cle = 'cmd:' + b.s;
        const brut = await env.SALONS.get(cle);
        if (brut) {
          const list = JSON.parse(brut).map(c => c.id === b.id ? { ...c, pris: true } : c);
          await env.SALONS.put(cle, JSON.stringify(list), { expirationTtl: RETENTION });
        }
        return json(200, { ok: true });
      }
      return json(404, { erreur: 'route inconnue' });
    } catch (e) {
      return json(400, { erreur: String((e && e.message) || e) });
    }
  }
};
