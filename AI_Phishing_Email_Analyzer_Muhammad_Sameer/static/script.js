const textarea = document.querySelector("textarea[name='email_body']");
if (textarea) {
    textarea.addEventListener("input", () => {
        textarea.style.height = "auto";
        textarea.style.height = textarea.scrollHeight + "px";
    });
}
