import { useMutation } from "@tanstack/react-query";
import { AxiosError } from "axios";

import { UseCustomMutationOptions } from "./helpers";
import { axiosInstance } from "./axios";

interface CheckUrlPatternResponse {
  is_phishing: boolean;
  level: number;
}

export const useCheckUrlPatternMutation = (
  options: UseCustomMutationOptions<
    CheckUrlPatternResponse,
    AxiosError,
    string
  >,
) => {
  return useMutation({
    ...options,
    mutationKey: ["check-url-pattern"],
    mutationFn: async (url: string) => {
      const response = await axiosInstance.post("/api/url/predict", {
        url,
      });

      return response.data;
    },
  });
};
