document.addEventListener("DOMContentLoaded", () => {
  const captcha = document.getElementById("captcha");
  if (!captcha) return;

  captcha.addEventListener("input", () => {
    captcha.value = captcha.value.replace(/[^0-9]/g, "");
  });
});
