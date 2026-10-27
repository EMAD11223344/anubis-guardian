const router = require("express").Router();
router.post("/promote", (req, res) => {
  if (req.body.isAdmin) { grant(req); }
  res.json({ ok: true });
});
