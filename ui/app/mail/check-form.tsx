"use client";
import { Button } from "@nextui-org/button";
import { Textarea } from "@nextui-org/input";
import { useRef, useState } from "react";
import { Card, CardHeader } from "@nextui-org/card";
import { Chip } from "@nextui-org/chip";
import { Progress } from "@nextui-org/progress";
import { Divider } from "@nextui-org/divider";

import { useCheckMailMutation } from "@/queries/check-mail";

export const UrlCheckForm = () => {
  const [text, setText] = useState("");

  const textRef = useRef<string>("");

  const { mutate, isPending, error, data } = useCheckMailMutation({
    onSuccess: (data) => {
      console.log(data);
    },
  });

  const handleSubmit = () => {
    if (text.trim()) {
      mutate(text);
      textRef.current = text;
    }
  };

  return (
    <div className="flex flex-col gap-4 mt-4">
      <div className="w-full flex flex-col gap-2 mt-4 max-w-lg m-auto">
        <Textarea
          placeholder="Введите текст письма"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <Button color="primary" isLoading={isPending} onClick={handleSubmit}>
          Проверить
        </Button>
      </div>

      {error && (
        <p className="text-danger">
          {error.message}:{" "}
          {JSON.stringify((error?.response?.data as any).detail)}
        </p>
      )}

      {data && !error && (
        <Card className="mt-4">
          <CardHeader className="flex gap-3">
            <div className="flex flex-col gap-1">
              <p className="text-lg ml-0 mr-auto">
                Результаты анализа для текста письма:{" "}
                {textRef.current.length > 30
                  ? textRef.current.slice(0, 30) + "..."
                  : textRef.current}
              </p>
              <div className="flex gap-2 items-center">
                <Chip
                  color={data.is_phishing ? "danger" : "success"}
                  variant="flat"
                >
                  {data.is_phishing ? "Фишинг" : "Безопасно"}
                </Chip>
                <div className="flex flex-row gap-2 items-center">
                  Уровень доверия к письму:
                  <Progress
                    className="w-36"
                    color={data.is_phishing ? "danger" : "success"}
                    value={data.level * 100}
                  />
                  <span className="text-small text-default-500">
                    {(data.level * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
            </div>
          </CardHeader>
          <Divider />
        </Card>
      )}
    </div>
  );
};
