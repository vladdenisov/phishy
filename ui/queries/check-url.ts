import { useMutation } from "@tanstack/react-query";
import { AxiosError } from "axios";

import { CheckHtmlResponse } from "./check-html";
import { UseCustomMutationOptions } from "./helpers";
import { axiosInstance } from "./axios";

export const useCheckUrlMutation = (
  options: UseCustomMutationOptions<CheckHtmlResponse, AxiosError, string>,
) => {
  return useMutation({
    ...options,
    mutationKey: ["check-url"],
    mutationFn: async (url: string) => {
      const response = await axiosInstance.post("/predict_url", {
        url,
        wait_for_load: 20000,
        disable_javascript: false,
      });

      return response.data;
    },
  });
};
