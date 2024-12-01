import {
  UseMutationOptions,
  UseQueryOptions,
  QueryKey,
  UseInfiniteQueryOptions,
  InfiniteData,
} from "@tanstack/react-query";

export type UseCustomQueryOptions<
  TQueryFnData = unknown,
  TError = Error,
  TData = TQueryFnData,
  TQueryKey extends QueryKey = QueryKey,
> = Omit<
  UseQueryOptions<TQueryFnData, TError, TData, TQueryKey>,
  "queryKey" | "queryFn"
>;

export type UseCustomInfiniteQueryOptions<
  TQueryFnData = unknown,
  TError = Error,
  TData = InfiniteData<TQueryFnData>,
  TQueryKey extends QueryKey = QueryKey,
> = Omit<
  UseInfiniteQueryOptions<TQueryFnData, TError, TData, TQueryKey>,
  "queryKey" | "queryFn" | "getNextPageParam"
>;

export type UseCustomMutationOptions<
  TData = unknown,
  TError = Error,
  TVariables = void,
  TContext = unknown,
> = Omit<
  UseMutationOptions<TData, TError, TVariables, TContext>,
  "mutationKey" | "mutationFn"
>;
