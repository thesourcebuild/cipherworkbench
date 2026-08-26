import { requireFormatTool } from "../catalogue/tool-meta";
import {
  readAction,
  readCaseStyle,
  readCount,
  readDirection,
  readEntityForm,
  readEntityScope,
  readIndent,
  readLength,
  readUrlMode,
  readRandomShape,
  readUuidVersion,
  OPTION_RANDOM_BYTES,
  OPTION_RANDOM_DISTINCT,
  OPTION_RANDOM_MAX,
  OPTION_RANDOM_MIN,
} from "../pure";
import type { FormatSpec } from "../spec";
import { optBool, optNumber } from "@ocs/contracts/pure";

/**
 * The header line: what this tool is about to do, in the settings actually chosen.
 *
 * Reads the spec and nothing else, so it is on screen before anything is typed -- which for the two
 * generators is the whole story, since there is no input to describe.
 */
export function describeSpec(spec: FormatSpec): string {
  const tool = requireFormatTool(spec.variant);
  const direction = readDirection(spec.options);

  switch (tool.kind) {
    case "url": {
      const mode = readUrlMode(spec.options);
      const flavour =
        mode === "component"
          ? "one component"
          : mode === "uri"
            ? "a whole URI"
            : "form-urlencoded";
      return `Percent-${direction}s as ${flavour}.`;
    }
    case "htmlentity": {
      if (direction === "decode") return "Resolves HTML and XML character references.";
      const scope = readEntityScope(spec.options) === "markup" ? "the five markup characters" : "everything non-ASCII";
      const form = readEntityForm(spec.options);
      const style = form === "named" ? "named where one exists" : `${form} numeric`;
      return `Escapes ${scope}, ${style}.`;
    }
    case "jwt":
      return "Reads a token's header and claims. Checks no signature.";
    case "json": {
      const action = readAction(spec.options, "format");
      if (action === "validate") return "Parses the document and reports the first error.";
      if (action === "minify") return "Strips every byte of insignificant whitespace.";
      return `Indents with ${indentLabel(spec)}, keeping numbers and key order exactly as written.`;
    }
    case "xml": {
      const action = readAction(spec.options, "format");
      if (action === "validate") return "Parses the document and reports the first error.";
      if (action === "minify") return "Strips whitespace between elements.";
      return `Indents with ${indentLabel(spec)}, leaving mixed content on one line.`;
    }
    case "case":
      return `Converts to ${readCaseStyle(spec.options)} case, line by line.`;
    case "uuid": {
      const version = readUuidVersion(spec.options);
      if (version === "nil" || version === "max") return `The ${version} UUID constant.`;
      const count = readCount(spec.options);
      const many = version === "v3" || version === "v5" ? "" : ` \u00d7 ${count}`;
      return `Generates UUID${version}${many}.`;
    }
    case "password":
      return `Generates ${readCount(spec.options)} × ${readLength(spec.options)} characters from a CSPRNG.`;
    /**
     * Says the range and the draw, because those are the two things that decide what comes out and
     * both are settings rather than input. "10 whole numbers from 1 to 100" is the sentence somebody
     * checks against what they meant to ask for.
     */
    case "random": {
      const count = readCount(spec.options);
      if (readRandomShape(spec.options) === "decimal") {
        return `Draws ${count} decimal${count === 1 ? "" : "s"} from [0, 1), uniformly.`;
      }
      const min = optNumber(spec.options, OPTION_RANDOM_MIN) ?? 1;
      const max = optNumber(spec.options, OPTION_RANDOM_MAX) ?? 100;
      const distinct = optBool(spec.options, OPTION_RANDOM_DISTINCT) ? ", no repeats" : "";
      return `Draws ${count} whole number${count === 1 ? "" : "s"} from ${min} to ${max} inclusive${distinct}.`;
    }
    case "randombytes": {
      const count = readCount(spec.options);
      const length = optNumber(spec.options, OPTION_RANDOM_BYTES) ?? 32;
      const each = count === 1 ? "" : " each";
      return `Generates ${count} × ${length} random bytes${each} from crypto.getRandomValues.`;
    }
  }
}

function indentLabel(spec: FormatSpec): string {
  const indent = readIndent(spec.options);
  if (indent === "tab") return "a tab";
  if (indent === "0") return "no indent";
  return `${indent} spaces`;
}
