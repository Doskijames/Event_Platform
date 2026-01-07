document.addEventListener("DOMContentLoaded", () => {
  const timer = document.getElementById("otp-timer");
  if (!timer) return;

  let seconds = 600;

  const interval = setInterval(() => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    timer.textContent = `${m}:${s.toString().padStart(2, "0")}`;

    if (--seconds < 0) {
      clearInterval(interval);
      timer.textContent = "Expired";
    }
  }, 1000);
});
