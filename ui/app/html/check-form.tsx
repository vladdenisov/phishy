"use client";
import { Button } from "@nextui-org/button";
import { Input, Textarea } from "@nextui-org/input";
import { useState } from "react";
import { Card, CardBody, CardHeader } from "@nextui-org/card";
import { Chip } from "@nextui-org/chip";
import { Progress } from "@nextui-org/progress";
import { Divider } from "@nextui-org/divider";

import { subtitle } from "@/components/primitives";
import { CheckHtmlResponse, useCheckHtmlMutation } from "@/queries/check-html";
import { useCheckUrlMutation } from "@/queries/check-url";

export const HtmlCheckForm = () => {
  const [html, setHtml] = useState("");
  const [url, setUrl] = useState("");

  const [data, setData] = useState<CheckHtmlResponse | null>(null);

  const { mutate, isPending } = useCheckHtmlMutation({
    onSuccess: (data) => {
      console.log(data);
      setData(data);
    },
  });

  const { mutate: mutateUrl, isPending: isPendingUrl } = useCheckUrlMutation({
    onSuccess: (data) => {
      console.log(data);
      setData(data);
    },
  });

  const handleSubmit = () => {
    if (html.trim()) {
      mutate(html);
    }
  };

  const handleSubmitUrl = () => {
    if (url.trim()) {
      mutateUrl(url);
    }
  };

  return (
    <div className="flex flex-col gap-4 mt-4">
      <div className="w-full flex flex-col gap-2 mt-4 max-w-lg m-auto">
        <h3 className={subtitle()}>Проверка HTML содержимого</h3>
        <Textarea
          placeholder="Вставьте HTML код"
          value={html}
          onChange={(e) => setHtml(e.target.value)}
        />
        <Button color="primary" isLoading={isPending} onClick={handleSubmit}>
          Проверить
        </Button>
      </div>

      <div className="w-full flex flex-col gap-2 mt-4 max-w-lg m-auto">
        <h3 className={subtitle()}>Проверка по URL</h3>
        <Input
          placeholder="Вставьте URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <Button
          color="primary"
          isLoading={isPendingUrl}
          onClick={handleSubmitUrl}
        >
          Проверить
        </Button>
      </div>

      {data && (
        <Card className="mt-4">
          <CardHeader className="flex gap-3">
            <div className="flex flex-col gap-1">
              <p className="text-lg ml-0 mr-auto">Результаты анализа</p>
              <div className="flex gap-2 items-center">
                <Chip
                  color={data.is_phishing ? "danger" : "success"}
                  variant="flat"
                >
                  {data.is_phishing ? "Фишинг" : "Безопасно"}
                </Chip>
                <Progress
                  aria-label="Уверенность"
                  className="w-36"
                  color={data.is_phishing ? "danger" : "success"}
                  value={data.confidence * 100}
                />
                <span className="text-small text-default-500">
                  {(data.confidence * 100).toFixed(1)}%
                </span>
              </div>
            </div>
          </CardHeader>
          <Divider />
          <CardBody>
            <div className="flex flex-col gap-4">
              <div>
                <p className="font-medium">Объяснение:</p>
                <p className="text-default-500">{data.explanation}</p>
              </div>

              <div>
                <p className="font-medium mb-2">Важные факторы:</p>
                <div className="flex flex-col gap-2">
                  {data.feature_importance.map(
                    ([feature, value, importance], index) => (
                      <div key={index} className="flex items-center gap-2">
                        <Chip size="sm" variant="flat">
                          {feature}
                        </Chip>
                        <div className="flex flex-row gap-2 w-1/2 ml-auto mr-0">
                          <span className="text-small text-default-500 whitespace-nowrap">
                            Значение: {value}
                          </span>
                          <Progress
                            aria-label="Важность"
                            className="w-1/2 mr-0 ml-auto"
                            color={importance > 0 ? "success" : "danger"}
                            maxValue={Math.max(
                              ...data.feature_importance.map((el) => el[2]),
                            )}
                            value={Math.abs(importance)}
                          />
                        </div>
                      </div>
                    ),
                  )}
                </div>
              </div>

              {data.suspicious_elements.length > 0 && (
                <div>
                  <p className="font-medium mb-2">Подозрительные элементы:</p>
                  <div className="flex flex-col gap-2">
                    {data.suspicious_elements.map((element, index) => (
                      <Card key={index} className="border-none bg-default-50">
                        <CardBody className="py-3">
                          <div className="flex gap-2 items-start">
                            <Chip
                              className="whitespace-nowrap"
                              color="warning"
                              variant="flat"
                            >
                              {element.type}
                            </Chip>
                            <div className="flex flex-col gap-1">
                              <p className="font-medium">{element.element}</p>
                              <p className="text-small text-default-500">
                                {element.issue}
                              </p>
                            </div>
                          </div>
                        </CardBody>
                      </Card>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
};
