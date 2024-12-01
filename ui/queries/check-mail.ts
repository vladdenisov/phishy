import { useMutation } from "@tanstack/react-query";
import { AxiosError } from "axios";

import { UseCustomMutationOptions } from "./helpers";
import { axiosInstance } from "./axios";

interface CheckMailResponse {
  is_phishing: boolean;
  level: number;
}

export const useCheckMailMutation = (
  options: UseCustomMutationOptions<CheckMailResponse, AxiosError, string>,
) => {
  return useMutation({
    ...options,
    mutationKey: ["check-mail"],
    mutationFn: async (mail: string) => {
      const response = await axiosInstance.post("/api/mail/predict", {
        mail,
      });

      return response.data;
    },
  });
};
