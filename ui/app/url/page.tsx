import { UrlCheckForm } from "./check-form";

import { title } from "@/components/primitives";

export default function UrlPage() {
  return (
    <div>
      <h2 className={title({ size: "sm" })}>Проверка URL</h2>
      <UrlCheckForm />
    </div>
  );
}
