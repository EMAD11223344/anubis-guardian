import multer from "multer";
const upload = multer({ limits: { fileSize: 5 * 1024 * 1024, files: 3 } });
app.post("/f", upload.single("file"), (req, res) => {
  fs.writeFile(path.join(".private-store", generateServerSideName()), req.file.buffer);
  res.json({ saved: true });
});
