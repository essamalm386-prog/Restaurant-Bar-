/* =========================================================================
   JARABA — Worker unique : serveur de liaison + tunnel de vente autonome
   -------------------------------------------------------------------------
   Déploiement : ce fichier remplace worker.js dans le dépôt GitHub connecté
   à Cloudflare. Le binding KV « SALONS » sert aux deux usages, avec des
   préfixes de clés distincts (liaison éphémère / ventes durables).

   Deux secrets à définir dans le Worker (Settings → Variables → Encrypt) :
     LIC_SEL     le sel qui fabrique les licences — jamais en clair ici,
                 ce dépôt étant public, quiconque le lirait pourrait créer des clés
     ADMIN_CLE   mot de passe de votre tableau de bord

   Facultatifs : MOMO_NUMERO, MOMO_NOM et SITE_VENTE remplacent les valeurs
   par défaut ci-dessous. CINETPAY_KEY et CINETPAY_SITE, s'ils sont renseignés,
   font basculer la boutique du règlement direct vers l'encaissement automatique.
   ========================================================================= */

const RETENTION = 10800;            /* liaison : 3 h */
const CP_API    = 'https://api-checkout.cinetpay.com/v2';

/* ---- Catalogue commercial : modifiable sans toucher au reste ------------ */
const FORMULES = {
  m1:  { mois: 1,  prix: 1000,  titre: '1 mois' },
  m6:  { mois: 6,  prix: 5000,  titre: '6 mois' },
  m12: { mois: 12, prix: 10000, titre: '12 mois' },
  m24: { mois: 24, prix: 15000, titre: '2 ans' }
};
const DEVISE = 'XAF';
const BONUS_FILLEUL = 1;            /* mois offerts à celui qui utilise un code */
const BONUS_PARRAIN  = 1;            /* mois offerts à celui qui l'a donné */

/* Coordonnées d'encaissement. Publiques par nature : elles s'affichent sur la
   boutique. Les secrets MOMO_NUMERO / MOMO_NOM les remplacent si définis. */
const MOMO_DEFAUT = { numero: '655 01 47 92', nom: 'Louis Marie ESSAMA' };

/* Adresse de la boutique, où le client est renvoyé après paiement.
   Publique elle aussi ; le secret SITE_VENTE la remplace si besoin. */
const SITE_DEFAUT = 'https://effortless-bonbon-5dd272.netlify.app';

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
/* Selon l'environnement, toLocaleString sépare les milliers par une espace fine
   insécable (U+202F) ou insécable (U+00A0) : on ramène tout à une espace simple. */
const fmtF = n => Number(n || 0).toLocaleString('fr-FR').replace(/[\s\u00a0\u202f]+/g, ' ') + ' F';

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
  const site = env.SITE_VENTE || SITE_DEFAUT || origine;
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

/* Fabrique et range la licence. Point de passage unique : que le paiement ait
   été confirmé par l'opérateur ou validé à la main, tout aboutit ici. */
async function emettre(env, id) {
  const dejaVendu = await env.SALONS.get('v:paye:' + id);
  if (dejaVendu) return JSON.parse(dejaVendu);
  const brut = await env.SALONS.get('v:cmd:' + id);
  if (!brut) return null;
  const cmd = JSON.parse(brut);

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
                            montant: cmd.montant, exp, parraine: !!cmd.parrainTel,
                            mode: cmd.mode || 'auto', date: vente.date });
  return vente;
}

/* Chemin automatique : le statut est revérifié en direct auprès de l'encaisseur
   avant toute livraison. La notification n'est jamais crue sur parole. */
async function livrer(env, id) {
  const dejaVendu = await env.SALONS.get('v:paye:' + id);
  if (dejaVendu) return JSON.parse(dejaVendu);
  const brut = await env.SALONS.get('v:cmd:' + id);
  if (!brut) return null;
  const cmd = JSON.parse(brut);
  if (cmd.mode === 'direct') return null;      /* validation humaine attendue */
  if (!env.CINETPAY_KEY) return null;

  const r = await fetch(CP_API + '/payment/check', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apikey: env.CINETPAY_KEY, site_id: env.CINETPAY_SITE, transaction_id: id })
  });
  const j = await r.json().catch(() => ({}));
  const st = (j && j.data && j.data.status) || (j && j.code) || '';
  if (!(st === 'ACCEPTED' || st === '00' || st === 'SUCCES')) return null;

  const montant = Number((j.data && j.data.amount) || 0);
  if (montant && montant < cmd.montant) return null;   /* montant insuffisant : on ne livre pas */
  return emettre(env, id);
}

/* ---- Encaissement direct, sans agrégateur -------------------------
   Le client envoie l'argent sur le Mobile Money du vendeur, puis déclare
   sa référence. Le vendeur confirme d'un geste depuis son tableau de bord
   et la clé part toute seule. Aucune inscription d'entreprise requise. */
async function declarer(req, env) {
  const b = await req.json();
  const etab = nettoyerNom(b.etab);
  const tel  = nettoyerTel(b.tel);
  const f    = FORMULES[b.formule];
  const refPaie = String(b.refPaiement || '').trim().replace(/[<>|]/g, '').slice(0, 40);
  if (!etab) return json(400, { erreur: "Indiquez le nom de votre établissement." });
  if (tel.length < 8) return json(400, { erreur: 'Indiquez un numéro de téléphone valide.' });
  if (!f) return json(400, { erreur: 'Formule inconnue.' });
  if (refPaie.length < 4)
    return json(400, { erreur: "Recopiez l'identifiant du message de confirmation de votre paiement." });

  let parrainTel = '';
  const code = String(b.parrain || '').trim().toUpperCase();
  if (code) {
    const t = await env.SALONS.get('v:parr:' + code);
    if (t && t !== tel) parrainTel = t;
  }
  const id = ref();
  await env.SALONS.put('v:cmd:' + id, JSON.stringify({
    id, etab, tel, formule: b.formule, mois: f.mois, montant: f.prix,
    parrainTel, mode: 'direct', refPaie, etat: 'a-verifier',
    date: new Date().toISOString()
  }), { expirationTtl: 86400 * 30 });

  const bl = await env.SALONS.get('v:attente');
  const liste = bl ? JSON.parse(bl) : [];
  liste.unshift({ id, etab, tel, refPaie, montant: f.prix,
                  formule: f.titre, date: new Date().toISOString() });
  await env.SALONS.put('v:attente', JSON.stringify(liste.slice(0, 500)));
  return json(200, { ok: true, ref: id });
}

/* Le vendeur confirme avoir vu l'argent arriver : la licence est émise. */
async function valider(url, req, env) {
  if (!env.ADMIN_CLE || url.searchParams.get('k') !== env.ADMIN_CLE)
    return json(401, { erreur: 'Accès refusé.' });
  const b = await req.json();
  const id = String(b.id || '');
  const refuser = !!b.refuser;

  const bl = await env.SALONS.get('v:attente');
  const liste = (bl ? JSON.parse(bl) : []).filter(x => x.id !== id);
  await env.SALONS.put('v:attente', JSON.stringify(liste));

  if (refuser) {
    await env.SALONS.put('v:refus:' + id, '1', { expirationTtl: 86400 * 30 });
    return json(200, { ok: true, refuse: true });
  }
  const v = await emettre(env, id);
  if (!v) return json(404, { erreur: 'Commande introuvable ou déjà traitée.' });
  return json(200, { ok: true, cle: v.cle, exp: v.exp });
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
  const ba = await env.SALONS.get('v:attente');
  const attente = ba ? JSON.parse(ba) : [];
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
h2.st{font-size:17px;font-weight:800;margin:26px 0 6px;display:flex;align-items:center;gap:9px}
.pill{background:#C99948;color:#241905;border-radius:999px;padding:2px 10px;font-size:12.5px}
.aide{font-size:13.5px;color:#84878D;margin:0 0 12px}
.att{background:#fff;border-radius:18px;padding:15px;margin-bottom:10px;
box-shadow:0 1px 3px rgba(27,28,30,.06);border-left:4px solid #C99948}
.att .hd{display:flex;justify-content:space-between;align-items:baseline;gap:10px}
.att .hd b{font-size:16.5px}
.att .mt{font-size:18px;font-weight:800;font-variant-numeric:tabular-nums;white-space:nowrap}
.att .mn{font-size:13px;color:#84878D;margin-top:3px}
.att .rf{font-size:14px;margin-top:9px;background:#F2F3F5;border-radius:12px;padding:9px 12px;
word-break:break-all}
.att .ac{display:flex;gap:9px;margin-top:12px}
.att button{flex:1;border:none;border-radius:999px;padding:12px;font-size:14.5px;font-weight:700;
font-family:inherit;cursor:pointer;min-height:46px}
.att .ok{background:#051D38;color:#fff}
.att .no{background:#F2F3F5;color:#C0392B}
.fait{background:#E6F4EC;color:#14512C;border-radius:16px;padding:14px;font-size:14.5px;
font-weight:600;margin-bottom:10px}
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

${attente.length ? `<h2 class="st">Paiements à confirmer <span class="pill">${attente.length}</span></h2>
<p class="aide">Vérifiez que la somme est bien arrivée sur votre Mobile Money, puis confirmez :
la clé part alors toute seule chez le client, qui la voit apparaître sur sa page.</p>
${attente.map(a => `<div class="att" id="a-${esc(a.id)}">
  <div class="hd"><b>${esc(a.etab)}</b><span class="mt">${fmtF(a.montant)}</span></div>
  <div class="mn">${esc(a.formule)} · ${esc(a.tel)} · ${esc((a.date || '').slice(0, 10))}</div>
  <div class="rf">Référence donnée : <b>${esc(a.refPaie)}</b></div>
  <div class="ac">
    <button class="ok" onclick="tranche('${esc(a.id)}',false)">J'ai reçu l'argent</button>
    <button class="no" onclick="tranche('${esc(a.id)}',true)">Refuser</button>
  </div></div>`).join('')}` : ''}

<h2 class="st">Historique</h2>
<table><tr><th>Date</th><th>Établissement</th><th>Téléphone</th><th>Formule</th>
<th style="text-align:right">Montant</th><th>Fin</th></tr>${lignes}</table>
<script>
var CLE = new URLSearchParams(location.search).get('k');
function tranche(id, refus){
  if(refus && !confirm('Refuser cette demande ?')) return;
  var bloc = document.getElementById('a-' + id);
  bloc.style.opacity = '.5';
  fetch('/vente/valider?k=' + encodeURIComponent(CLE), {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id:id, refuser:refus})
  }).then(function(r){ return r.json(); }).then(function(j){
    if(j.ok){ bloc.outerHTML = '<div class="fait">' + (refus ? 'Refusé.'
      : 'Licence délivrée jusqu\\'à fin ' + j.exp + ' — le client la reçoit à l\\'instant.') + '</div>'; }
    else { bloc.style.opacity = '1'; alert(j.erreur || 'Impossible.'); }
  }).catch(function(){ bloc.style.opacity = '1'; alert('Pas de réseau.'); });
}
</script>
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
        return json(200, {
          devise: DEVISE, formules: FORMULES,
          /* « auto » dès qu'un encaisseur est configuré, « direct » sinon */
          paiement: (env.CINETPAY_KEY && env.CINETPAY_SITE) ? 'auto' : 'direct',
          momo: env.MOMO_NUMERO || MOMO_DEFAUT.numero,
          momoNom: env.MOMO_NOM || MOMO_DEFAUT.nom
        });
      if (chemin === '/vente/declarer' && req.method === 'POST') return declarer(req, env);
      if (chemin === '/vente/valider'  && req.method === 'POST') return valider(u, req, env);
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
