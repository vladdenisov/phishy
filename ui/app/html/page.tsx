import { HtmlCheckForm } from "./check-form";

import { title } from "@/components/primitives";
export default function HtmlPage() {
  return (
    <div>
      <h2 className={title({ size: "sm" })}>Проверка вебсайта</h2>
      <HtmlCheckForm />
    </div>
  );
}
