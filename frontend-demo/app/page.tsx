// Provide a minimal JSX declaration so the compiler recognizes intrinsic elements
declare global {
  namespace JSX {
    interface IntrinsicElements {
      [elemName: string]: any;
    }
  }
}
export default function Home() {
  return (
    <main style={{padding:20}}>
      <h1>HALP Demo Frontend</h1>
      <p>Use /issue and /authenticate pages to experiment with the backend services.</p>
    </main>
  );
}
