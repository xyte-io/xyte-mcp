import type { z, ZodRawShape } from 'zod';
import type { ToolContext } from '../context.js';

export interface ToolTextContent {
  type: 'text';
  text: string;
}

export interface ToolResult {
  content: ToolTextContent[];
  structuredContent?: Record<string, unknown>;
  /**
   * Failures come back as results, not protocol errors, so the model can read
   * what went wrong and try again.
   */
  isError?: boolean;
  /** MCP tool results are open (`_meta`, future fields), hence the index signature. */
  [key: string]: unknown;
}

/** Hints hosts use to decide whether to prompt before running a tool. */
export interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolDefinition<TShape extends ZodRawShape = ZodRawShape> {
  name: string;
  title: string;
  description: string;
  inputSchema: TShape;
  outputSchema?: ZodRawShape;
  /** Computed from context so the write policy is reflected to the host. */
  annotations: (context: ToolContext) => ToolAnnotations;
  handler: (
    args: z.infer<z.ZodObject<TShape>>,
    context: ToolContext
  ) => Promise<ToolResult> | ToolResult;
}

/** Identity helper that preserves the input-schema generic. */
export function defineTool<TShape extends ZodRawShape>(
  definition: ToolDefinition<TShape>
): ToolDefinition<TShape> {
  return definition;
}

/**
 * A tool with its input-schema generic erased, so differently-shaped tools can
 * live in one registry.
 */
export interface AnyToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: ZodRawShape;
  outputSchema?: ZodRawShape;
  annotations: (context: ToolContext) => ToolAnnotations;
  handler: (
    args: Record<string, unknown>,
    context: ToolContext
  ) => Promise<ToolResult> | ToolResult;
}

/**
 * Erase the generic for registration. The cast is safe because the SDK
 * validates arguments against `inputSchema` before the handler is invoked, so
 * the handler always receives the shape it declared. Confined to this one place.
 */
export function eraseTool<TShape extends ZodRawShape>(
  definition: ToolDefinition<TShape>
): AnyToolDefinition {
  return definition as unknown as AnyToolDefinition;
}

export function textResult(
  text: string,
  structuredContent?: Record<string, unknown>
): ToolResult {
  return {
    content: [{ type: 'text', text }],
    ...(structuredContent ? { structuredContent } : {})
  };
}

export function errorResult(message: string, hints: readonly string[] = []): ToolResult {
  const text = hints.length ? `${message}\n\n${hints.map((h) => `- ${h}`).join('\n')}` : message;
  return { content: [{ type: 'text', text }], isError: true };
}
