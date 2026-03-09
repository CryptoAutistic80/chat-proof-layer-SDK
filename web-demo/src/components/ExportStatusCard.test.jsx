import React from "react";
import { MemoryRouter } from "react-router-dom";
import { render, screen } from "@testing-library/react";
import { describe, expect, test, vi } from "vitest";
import { ExportStatusCard } from "./ExportStatusCard";

describe("ExportStatusCard", () => {
  test("shows a clear no-export explanation for empty disclosure output", () => {
    render(
      <MemoryRouter>
        <ExportStatusCard
          run={{
            bundleId: "01-test",
            bundleFormat: "disclosure",
            disclosurePreview: {
              disclosed_item_indices: [],
              disclosed_artefact_names: []
            }
          }}
          onExport={vi.fn()}
          isExporting={false}
        />
      </MemoryRouter>
    );

    expect(
      screen.getByText("No disclosure pack to export for this run with the selected profile.")
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Export pack" }).disabled).toBe(true);
  });
});
