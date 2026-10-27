import AdmZip from "adm-zip";
export function extract(buf: Buffer, out: string) {
  const z = new AdmZip(buf);
  z.getEntries()
    .filter((e) => !e.entryName.includes("..") && e.header.size < MAX_ENTRY && count < MAX_ENTRIES)
    .forEach((e) => z.extractEntryTo(e, join(out, path.basename(e.entryName))));
}
