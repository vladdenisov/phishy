import { Button, ButtonGroup } from "@nextui-org/button";

export default function Home() {
  return (
    <section className="flex flex-col items-center justify-center gap-4 py-8 md:py-10">
      <h1 className="text-4xl font-bold">Детектор фишинга</h1>
      <ButtonGroup>
        <Button>Проверить вебсайт</Button>
        <Button>Проверить email</Button>
      </ButtonGroup>
    </section>
  );
}
