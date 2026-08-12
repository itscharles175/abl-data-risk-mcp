import { createHash } from "node:crypto";

export type NotificationChannelV1 = "email" | "teams" | "slack" | "webhook";

export interface NotificationDestinationV1 {
  readonly destinationId: string;
  readonly channel: NotificationChannelV1;
  /** Opaque resolver reference; no address/URL/token is stored in this directory. */
  readonly targetRef: string;
  readonly status: "active" | "retired";
  readonly createdBy: string;
  readonly approvedBy: string;
}

export interface NotificationTemplateV1 {
  readonly templateId: string;
  readonly channel: NotificationChannelV1;
  readonly subject: string;
  readonly body: string;
  readonly allowedVariables: readonly string[];
  readonly status: "active" | "retired";
  readonly createdBy: string;
  readonly approvedBy: string;
}

export interface NotificationDirectory {
  getDestination(id: string): NotificationDestinationV1 | undefined;
  getTemplate(id: string): NotificationTemplateV1 | undefined;
}

export interface ResolvedNotificationTargetV1 {
  readonly destinationId: string;
  readonly channel: NotificationChannelV1;
  readonly address: string;
}

export interface NotificationTargetResolver {
  resolve(targetRef: string, destinationId: string, signal?: AbortSignal): Promise<ResolvedNotificationTargetV1>;
}

export interface NotificationSender {
  send(input: { readonly target: ResolvedNotificationTargetV1; readonly subject: string; readonly body: string; readonly idempotencyKey: string }, signal?: AbortSignal): Promise<{ readonly providerReceipt: string }>;
}

export interface DispatchGovernedNotificationInputV1 {
  readonly destinationId: string;
  readonly templateId: string;
  readonly variables: Readonly<Record<string, string>>;
  readonly idempotencyKey: string;
}

export interface NotificationDeliveryReceiptV1 {
  readonly destinationId: string;
  readonly templateId: string;
  readonly channel: NotificationChannelV1;
  readonly payloadHash: string;
  readonly providerReceiptHash: string;
}

export class NotificationDispatchError extends Error {
  constructor(readonly code: "INVALID_INPUT" | "NOT_APPROVED" | "RESOLUTION_FAILED" | "DELIVERY_FAILED", message: string) {
    super(message);
    this.name = "NotificationDispatchError";
  }
}

export class InMemoryNotificationDirectory implements NotificationDirectory {
  readonly #destinations = new Map<string, NotificationDestinationV1>();
  readonly #templates = new Map<string, NotificationTemplateV1>();

  constructor(destinations: readonly NotificationDestinationV1[], templates: readonly NotificationTemplateV1[]) {
    for (const destination of destinations) {
      validateDestination(destination);
      if (this.#destinations.has(destination.destinationId)) invalid("Duplicate destination");
      this.#destinations.set(destination.destinationId, Object.freeze(destination));
    }
    for (const template of templates) {
      validateTemplate(template);
      if (this.#templates.has(template.templateId)) invalid("Duplicate template");
      this.#templates.set(template.templateId, Object.freeze({ ...template, allowedVariables: Object.freeze([...template.allowedVariables]) }));
    }
  }

  getDestination(id: string): NotificationDestinationV1 | undefined { return this.#destinations.get(id); }
  getTemplate(id: string): NotificationTemplateV1 | undefined { return this.#templates.get(id); }
}

export async function dispatchGovernedNotification(
  input: DispatchGovernedNotificationInputV1,
  dependencies: { readonly directory: NotificationDirectory; readonly resolver: NotificationTargetResolver; readonly sender: NotificationSender },
  signal?: AbortSignal
): Promise<NotificationDeliveryReceiptV1> {
  identifier(input.destinationId); identifier(input.templateId); identifier(input.idempotencyKey);
  const destination = dependencies.directory.getDestination(input.destinationId);
  const template = dependencies.directory.getTemplate(input.templateId);
  if (!destination || !template || destination.status !== "active" || template.status !== "active" || destination.channel !== template.channel) {
    throw new NotificationDispatchError("NOT_APPROVED", "Notification destination/template is not active and compatible");
  }
  const actualVariables = Object.keys(input.variables).sort();
  const allowed = [...template.allowedVariables].sort();
  if (actualVariables.length !== allowed.length || actualVariables.some((value, index) => value !== allowed[index])) invalid("Notification variables do not match the approved template");
  for (const [name, value] of Object.entries(input.variables)) {
    identifier(name);
    if (typeof value !== "string" || value.length > 2_000 || /(?:https?:\/\/|mailto:|@everyone|<script)/iu.test(value)) invalid("Notification variable contains disallowed delivery or active-content text");
  }
  signal?.throwIfAborted();
  let target: ResolvedNotificationTargetV1;
  try { target = await dependencies.resolver.resolve(destination.targetRef, destination.destinationId, signal); }
  catch { throw new NotificationDispatchError("RESOLUTION_FAILED", "Notification target could not be resolved"); }
  if (target.destinationId !== destination.destinationId || target.channel !== destination.channel) throw new NotificationDispatchError("RESOLUTION_FAILED", "Resolved target did not match the approved destination");
  const subject = render(template.subject, input.variables);
  const body = render(template.body, input.variables);
  const payloadHash = sha256(JSON.stringify({ body, destinationId: destination.destinationId, subject, templateId: template.templateId }));
  let delivery: { readonly providerReceipt: string };
  try { delivery = await dependencies.sender.send({ target, subject, body, idempotencyKey: input.idempotencyKey }, signal); }
  catch { throw new NotificationDispatchError("DELIVERY_FAILED", "Notification delivery failed"); }
  if (!delivery.providerReceipt || delivery.providerReceipt.length > 2_000) throw new NotificationDispatchError("DELIVERY_FAILED", "Notification provider receipt is invalid");
  return Object.freeze({
    destinationId: destination.destinationId,
    templateId: template.templateId,
    channel: destination.channel,
    payloadHash,
    providerReceiptHash: sha256(delivery.providerReceipt)
  });
}

function render(template: string, variables: Readonly<Record<string, string>>): string {
  const rendered = template.replace(/\{\{([A-Za-z0-9_.-]+)\}\}/gu, (_match, name: string) => variables[name] ?? "");
  if (/\{\{|\}\}/u.test(rendered)) invalid("Notification template contains an unresolved placeholder");
  return rendered;
}

function validateDestination(value: NotificationDestinationV1): void {
  identifier(value.destinationId); identifier(value.createdBy); identifier(value.approvedBy);
  if (value.createdBy === value.approvedBy) invalid("Destination maker and checker must differ");
  if (!(["email", "teams", "slack", "webhook"] as const).includes(value.channel)) invalid("Destination channel is invalid");
  if (!/^secretref:\/\/[A-Za-z0-9._:@/-]+#[A-Za-z0-9._-]+$/u.test(value.targetRef)) invalid("Destination must contain only an opaque versioned secret reference");
}

function validateTemplate(value: NotificationTemplateV1): void {
  identifier(value.templateId); identifier(value.createdBy); identifier(value.approvedBy);
  if (value.createdBy === value.approvedBy) invalid("Template maker and checker must differ");
  if (!value.subject || value.subject.length > 256 || !value.body || value.body.length > 8_000) invalid("Notification template content is invalid");
  if (new Set(value.allowedVariables).size !== value.allowedVariables.length || value.allowedVariables.length > 50) invalid("Template variables are invalid");
  const referenced = [...`${value.subject}\n${value.body}`.matchAll(/\{\{([A-Za-z0-9_.-]+)\}\}/gu)].map((match) => match[1]!);
  if (referenced.some((variable) => !value.allowedVariables.includes(variable))) invalid("Template references an unapproved variable");
}

function identifier(value: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u.test(value)) invalid("Identifier is invalid");
}

function sha256(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }

function invalid(message: string): never { throw new NotificationDispatchError("INVALID_INPUT", message); }
