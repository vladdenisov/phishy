export default function UrlLayout({ children }: { children: React.ReactNode }) {
  return (
    <section className="flex flex-col items-center justify-center gap-4">
      <div className="inline-block w-3/4 text-center justify-center">
        {children}
      </div>
    </section>
  );
}
