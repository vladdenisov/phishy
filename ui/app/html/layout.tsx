export default function HtmlLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col items-center justify-center gap-4 sm:pb-5">
      <div className="inline-block w-3/4 text-center justify-center sm:w-full">
        {children}
      </div>
    </section>
  );
}
