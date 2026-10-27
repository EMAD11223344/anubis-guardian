import AdmZip from "adm-zip";
import { createReadStream } from "fs";
export function extract(buf: Buffer, out: string) {
  const z = new AdmZip(buf);
  z.extractAllTo(out);
}
app.post("/import", (req, res) => {
  createReadStream(req.body.path).pipe(require("tar").x({ cwd: "/var/www/ex" }));
});
