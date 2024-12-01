import { useMutation } from "@tanstack/react-query";

import { UseCustomMutationOptions } from "./helpers";
import { axiosInstance } from "./axios";

export interface FeatureImportance {
  feature: string;
  value: number;
  importance: number;
}

export interface FeatureValues {
  form_count: number;
  password_fields: number;
  external_form_actions: number;
  link_count: number;
  external_links_ratio: number;
  suspicious_link_ratio: number;
  script_count: number;
  external_scripts: number;
  meta_tag_count: number;
  has_favicon: number;
  has_title: number;
  title_length: number;
  hidden_element_count: number;
  has_https_link: number;
  has_security_text: number;
  text_length: number;
  has_urgent_text: number;
  input_field_count: number;
  sensitive_input_count: number;
  has_submit_button: number;
}

export interface SuspiciousElement {
  element: string;
  issue: string;
  type: string;
}

export interface CheckHtmlResponse {
  is_phishing: boolean;
  confidence: number;
  explanation: string;
  feature_importance: [string, number, number][];
  suspicious_elements: SuspiciousElement[];
  feature_values: FeatureValues;
}

export const useCheckHtmlMutation = (
  options: UseCustomMutationOptions<CheckHtmlResponse, Error, string>,
) => {
  return useMutation({
    ...options,
    mutationKey: ["check-html"],
    mutationFn: async (html: string) => {
      const response = await axiosInstance.post("/predict", {
        html_content: html,
      });

      return response.data;
    },
  });
};
