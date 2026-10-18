import {
  DashboardStats,
  SBOM,
  ScanResult,
  SBOMDiff,
  RemediationGuidance,
  PatchResult,
} from "../types";

const BASE_URL = "";

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorMsg = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errorMsg);
  }
  return res.json();
}

export const api = {
  // ─── Dashboard ─────────────────────────────────────────────────────────────
  async getDashboardStats(): Promise<DashboardStats> {
    const res = await fetch(`${BASE_URL}/api/v1/dashboard/stats`);
    const data = await handleResponse<{ status: string; data: DashboardStats }>(res);
    return data.data;
  },

  // ─── SBOM ──────────────────────────────────────────────────────────────────
  async generateSBOM(
    file: File,
    format: "cyclonedx" | "spdx" = "cyclonedx",
    projectName?: string
  ): Promise<any> {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("format", format);
    if (projectName) formData.append("project_name", projectName);

    const res = await fetch(`${BASE_URL}/api/v1/sbom/generate`, {
      method: "POST",
      body: formData,
    });
    return handleResponse<any>(res);
  },

  async listSBOMs(): Promise<SBOM[]> {
    const res = await fetch(`${BASE_URL}/api/v1/sbom/list`);
    const data = await handleResponse<{ status: string; data: SBOM[] }>(res);
    return data.data;
  },

  async getSBOM(id: string): Promise<SBOM> {
    const res = await fetch(`${BASE_URL}/api/v1/sbom/${id}`);
    const data = await handleResponse<{ status: string; data: SBOM }>(res);
    return data.data;
  },

  async deleteSBOM(id: string): Promise<boolean> {
    const res = await fetch(`${BASE_URL}/api/v1/sbom/${id}`, {
      method: "DELETE",
    });
    await handleResponse(res);
    return true;
  },

  async compareSBOMs(sbomAId: string, sbomBId: string): Promise<SBOMDiff> {
    const res = await fetch(`${BASE_URL}/api/v1/sbom/compare`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        sbom_a_id: sbomAId,
        sbom_b_id: sbomBId,
      }),
    });
    const data = await handleResponse<{ status: string; data: SBOMDiff }>(res);
    return data.data;
  },

  // ─── Vulnerability ─────────────────────────────────────────────────────────
  async scanSBOM(sbomId: string): Promise<ScanResult> {
    const res = await fetch(`${BASE_URL}/api/v1/vulnerability/scan/${sbomId}`, {
      method: "POST",
    });
    const data = await handleResponse<{ status: string; data: ScanResult }>(res);
    return data.data;
  },

  async getScanResult(scanId: string): Promise<ScanResult> {
    const res = await fetch(`${BASE_URL}/api/v1/vulnerability/scan/${scanId}/result`);
    const data = await handleResponse<{ status: string; data: ScanResult }>(res);
    return data.data;
  },

  async listScans(): Promise<any[]> {
    const res = await fetch(`${BASE_URL}/api/v1/vulnerability/scans`);
    const data = await handleResponse<{ status: string; data: any[] }>(res);
    return data.data;
  },

  // ─── Remediation ───────────────────────────────────────────────────────────
  async getRemediationPlan(scanId: string): Promise<RemediationGuidance[]> {
    const res = await fetch(`${BASE_URL}/api/v1/remediation/scan/${scanId}`);
    const data = await handleResponse<{ status: string; data: RemediationGuidance[] }>(res);
    return data.data;
  },

  async generatePatch(
    manifestContent: string,
    filename: string,
    scanId?: string
  ): Promise<PatchResult> {
    const res = await fetch(`${BASE_URL}/api/v1/remediation/patch`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        manifest_content: manifestContent,
        filename: filename,
        scan_id: scanId,
      }),
    });
    const data = await handleResponse<{ status: string; data: PatchResult }>(res);
    return data.data;
  },
};
