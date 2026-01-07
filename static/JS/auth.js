document.addEventListener("DOMContentLoaded", () => {
  const pw = document.getElementById("password");
  if (!pw) return;

  const bar = document.getElementById("pw-bar");
  const text = document.getElementById("pw-text");

  pw.addEventListener("input", () => {
    let score = 0;
    const val = pw.value;

    if (val.length >= 8) score++;
    if (/[A-Za-z]/.test(val)) score++;
    if (/\d/.test(val)) score++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(val)) score++;

    bar.style.width = `${score * 25}%`;
    bar.className = score < 2 ? "pw-weak" : score < 4 ? "pw-medium" : "pw-strong";
    text.textContent =
      score < 2 ? "Weak" : score < 4 ? "Medium" : "Strong";
  });
});
