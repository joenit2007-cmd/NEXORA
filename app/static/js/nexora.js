/* NEXORA Interactive SOC Controls & Charts */

document.addEventListener("DOMContentLoaded", () => {
  // Mobile sidebar toggle
  const toggleBtn = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("nexoraSidebar");
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }

  // Live UTC Clock in Topbar
  const clockEl = document.getElementById("socUtcClock");
  if (clockEl) {
    const updateClock = () => {
      const now = new Date();
      clockEl.textContent = now.toISOString().replace("T", " ").slice(0, 19) + " UTC";
    };
    updateClock();
    setInterval(updateClock, 1000);
  }

  // Phishing Sample Fill Buttons
  document.querySelectorAll("[data-phish-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const preset = btn.getAttribute("data-phish-preset");
      const senderEl = document.getElementById("phishSender");
      const subjectEl = document.getElementById("phishSubject");
      const urlsEl = document.getElementById("phishUrls");
      const contentEl = document.getElementById("phishContent");
      if (!senderEl || !contentEl) return;

      if (preset === "high") {
        senderEl.value = "security-notice@paypal-account-verify.xyz";
        subjectEl.value = "URGENT: Unauthorized login detected - account will be closed within 24 hours";
        urlsEl.value = "http://198.51.100.25/paypal/verify-login";
        contentEl.value =
          "Dear Customer,\n\nWe detected an unauthorized login attempt on your PayPal account. " +
          "Act immediately and verify your password within 24 hours or your account will be suspended immediately.\n\n" +
          "Verify here: http://198.51.100.25/paypal/verify-login\n" +
          "Also open the attached invoice_details.zip and enable macros to confirm billing.";
      } else if (preset === "suspicious") {
        senderEl.value = "helpdesk-alerts@gmail.com";
        subjectEl.value = "IT Helpdesk: Mailbox quota exceeded";
        urlsEl.value = "https://bit.ly/3xQuotaReset";
        contentEl.value =
          "Hello,\n\nYour mailbox quota exceeded 98%. Please click the link below to validate your mailbox before end of day:\n" +
          "https://bit.ly/3xQuotaReset\n\nThank you,\nIT Helpdesk";
      } else if (preset === "safe") {
        senderEl.value = "project-updates@company-engineering.org";
        subjectEl.value = "Weekly Engineering Standup Notes";
        urlsEl.value = "";
        contentEl.value =
          "Hi team,\n\nThanks for joining today's standup. Summary notes and Q4 milestone dates have been updated in the " +
          "internal wiki. Please share any deployment blockers before Thursday afternoon.\n\nBest regards,\nEngineering Operations";
      }
    });
  });

  // Quick Target Preset Buttons (Authorized Local/Private Lab)
  document.querySelectorAll("[data-target-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetVal = btn.getAttribute("data-target-preset");
      const portsVal = btn.getAttribute("data-ports-preset") || "";
      const targetInput = document.getElementById("scanTargetInput") || document.getElementById("vulnTargetInput");
      const portsInput = document.getElementById("scanPortsInput") || document.getElementById("vulnPortsInput");
      if (targetInput) targetInput.value = targetVal;
      if (portsInput && portsVal) portsInput.value = portsVal;
    });
  });

  // Loading indicator on scan/assessment forms
  document.querySelectorAll("form[data-loading-text]").forEach((form) => {
    form.addEventListener("submit", () => {
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        const text = form.getAttribute("data-loading-text") || "Processing...";
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status"></span>${text}`;
      }
    });
  });
});

// Initialize Dashboard Charts when data payload exists
window.initNexoraDashboardCharts = function (chartData) {
  if (typeof Chart === "undefined" || !chartData) return;

  Chart.defaults.color = "#94a3b8";
  Chart.defaults.borderColor = "rgba(148, 163, 184, 0.12)";

  const activityCanvas = document.getElementById("securityActivityChart");
  if (activityCanvas) {
    new Chart(activityCanvas, {
      type: "line",
      data: {
        labels: chartData.timeline_labels || [],
        datasets: [
          {
            label: "Security Activity Events",
            data: chartData.timeline_values || [],
            borderColor: "#00d4ff",
            backgroundColor: "rgba(0, 212, 255, 0.14)",
            borderWidth: 2.5,
            fill: true,
            tension: 0.35,
            pointRadius: 4,
            pointBackgroundColor: "#00d4ff",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
        },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });
  }

  const sevCanvas = document.getElementById("severityDistChart");
  if (sevCanvas) {
    const dist = chartData.severity_distribution || {};
    const values = [
      dist.Critical || 0,
      dist.High || 0,
      dist.Medium || 0,
      dist.Low || 0,
      dist.Informational || 0,
    ];
    new Chart(sevCanvas, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Informational"],
        datasets: [
          {
            data: values.some((v) => v > 0) ? values : [0, 0, 0, 0, 1],
            backgroundColor: values.some((v) => v > 0)
              ? ["#ef4444", "#f97316", "#eab308", "#22c55e", "#38bdf8"]
              : ["#1e293b", "#1e293b", "#1e293b", "#1e293b", "#334155"],
            borderColor: "#111a2e",
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "66%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { boxWidth: 12, padding: 12 },
          },
        },
      },
    });
  }
};
