export default function JsonBlock({ title = "Raw JSON", data }) {
  return (
    <details className="json-block">
      <summary>{title}</summary>
      <pre>{JSON.stringify(data || {}, null, 2)}</pre>
    </details>
  );
}
