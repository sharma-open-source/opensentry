// Text chunking for Tier 1 ML — Llama-Prompt-Guard-2 has a 512-token input limit.
// "inputs >512 tok chunked in parallel with max-aggregate".
// We use a rough char-based token estimate (~4 chars/token for English) and split
// on sentence boundaries first, then hard-split if a single sentence exceeds the limit.

const CHARS_PER_TOKEN = 4; // rough estimate for DeBERTa subword tokenizer
const DEFAULT_MAX_TOKENS = 512;
const SAFETY_MARGIN = 0.85; // stay at 85% of max to account for tokenizer variance

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}

export function chunkText(text: string, maxTokens: number = DEFAULT_MAX_TOKENS): string[] {
  const maxChars = Math.floor(maxTokens * SAFETY_MARGIN * CHARS_PER_TOKEN);
  if (text.length <= maxChars) return [text];

  const chunks: string[] = [];
  // Split on sentence boundaries (period/space, exclamation/space, question/space, or newlines).
  const sentences = text.split(/(?<=[.!?])\s+|\n+/);
  let current = '';

  for (const sentence of sentences) {
    if (sentence.length > maxChars) {
      // Flush current chunk first
      if (current) {
        chunks.push(current);
        current = '';
      }
      // Hard-split very long sentences at word boundaries
      let remaining = sentence;
      while (remaining.length > maxChars) {
        let cut = maxChars;
        // Try to cut at a space
        const spaceIdx = remaining.lastIndexOf(' ', cut);
        if (spaceIdx > maxChars * 0.5) cut = spaceIdx;
        chunks.push(remaining.slice(0, cut));
        remaining = remaining.slice(cut).trimStart();
      }
      if (remaining) current = remaining;
    } else if (`${current} ${sentence}`.length > maxChars) {
      if (current) chunks.push(current);
      current = sentence;
    } else {
      current = current ? `${current} ${sentence}` : sentence;
    }
  }
  if (current) chunks.push(current);
  return chunks.length > 0 ? chunks : [text];
}
