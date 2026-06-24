// Minimal ambient type declaration for @huggingface/transformers — an optional peer
// dependency used by opensentry/onnx and opensentry/wasm. The actual package ships its
// own types; this stub avoids a hard TS error when the package is not installed.
// The runtime code uses structural typing (TransformersModule) and casts, so this
// declaration only needs to make the module resolvable.

declare module '@huggingface/transformers' {
  export const pipeline: (
    task: string,
    model: string,
    options?: { device?: string; dtype?: string },
  ) => Promise<
    (text: string, options?: { top_k?: number }) => Promise<Array<{ label: string; score: number }>>
  >;
  export const env: {
    allowLocalModels: boolean;
    allowRemoteModels: boolean;
    localModelPath: string;
    backends: {
      onnx: {
        wasm: {
          wasmPaths: string | undefined;
          numThreads: number;
          proxy: boolean;
        };
      };
    };
  };
}
