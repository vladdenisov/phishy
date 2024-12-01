"use client";
import { Button } from "@nextui-org/button";
import { Input } from "@nextui-org/input";
import { useRef, useState } from "react";
import { Card, CardHeader } from "@nextui-org/card";
import { Chip } from "@nextui-org/chip";
import { Progress } from "@nextui-org/progress";
import { Divider } from "@nextui-org/divider";

import { subtitle } from "@/components/primitives";
import { useCheckUrlPatternMutation } from "@/queries/check-url-pattern";

export const UrlCheckForm = () => {
  const [url, setUrl] = useState("");

  const urlRef = useRef<string>("");

  const { mutate, isPending, error, data } = useCheckUrlPatternMutation({
    onSuccess: (data) => {
      console.log(data);
    },
  });

  const handleSubmit = () => {
    if (url.trim()) {
      mutate(url);
      urlRef.current = url;
    }
  };

  return (
    <div className="flex flex-col gap-4 mt-4">
      <div className="w-full flex flex-col gap-2 mt-4 max-w-lg m-auto">
        <h3 className={subtitle()}>Проверка URL</h3>
        <Input
          placeholder="Вставьте URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
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
                Результаты анализа для URL:{" "}
                {urlRef.current.length > 30
                  ? urlRef.current.slice(0, 30) + "..."
                  : urlRef.current}
              </p>
              <div className="flex gap-2 items-center">
                <Chip
                  color={data.is_phishing ? "danger" : "success"}
                  variant="flat"
                >
                  {data.is_phishing ? "Фишинг" : "Безопасно"}
                </Chip>
                <div className="flex flex-row gap-2 items-center">
                  Уровень доверия к URL:
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
