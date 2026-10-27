import multer from "multer";
const upload = multer({ dest: ".uploads-tmp" });
app.post("/f", upload.single("file"), (req, res) => {
  fs.writeFile(path.join("public/assets", req.file.originalname), req.file.buffer);
  res.json({ saved: true });
});
