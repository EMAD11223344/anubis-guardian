export function Content() {
  const html = "<p>Static trusted content</p>";
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
