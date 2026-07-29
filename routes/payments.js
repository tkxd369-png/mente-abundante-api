const express = require('express');
const router = express.Router();
// Verificar que el módulo está funcionando
router.get('/status', async (req, res) => {
res.json({
ok: true,
message: 'Payments module ready',
stripe: false
});
});
// Próximamente: Crear Checkout de Stripe
router.post('/create-checkout', async (req, res) => {
res.json({
ok: true,
message: 'Coming soon'
});
});
// Próximamente: Webhook de Stripe
router.post('/webhook', async (req, res) => {
res.json({
ok: true,
message: 'Coming soon'
});
});
// Próximamente: Reactivar membresía
router.post('/reactivate', async (req, res) => {
res.json({
ok: true,
message: 'Coming soon'
});
});
module.exports = router;
