document.addEventListener("DOMContentLoaded", () => {
  const images = document.querySelectorAll(".post-article img");
  if (!images.length) {
    return;
  }

  const modal = document.createElement("div");
  modal.className = "image-modal";
  modal.setAttribute("aria-hidden", "true");
  modal.innerHTML = `
    <div class="image-modal__frame" role="dialog" aria-modal="true" aria-label="Expanded image view">
      <button class="image-modal__close" type="button" aria-label="Close image viewer">Close</button>
      <img class="image-modal__image" alt="" />
      <div class="image-modal__caption"></div>
    </div>
  `;

  document.body.appendChild(modal);

  const modalImage = modal.querySelector(".image-modal__image");
  const modalCaption = modal.querySelector(".image-modal__caption");
  const closeButton = modal.querySelector(".image-modal__close");

  function closeModal() {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    modalImage.src = "";
    modalImage.alt = "";
    modalCaption.textContent = "";
    document.body.style.overflow = "";
  }

  function openModal(image) {
    modalImage.src = image.currentSrc || image.src;
    modalImage.alt = image.alt || "Expanded post image";
    modalCaption.textContent = image.alt || "";
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
  }

  images.forEach((image) => {
    image.addEventListener("click", () => openModal(image));
  });

  closeButton.addEventListener("click", closeModal);

  modal.addEventListener("click", (event) => {
    if (event.target === modal) {
      closeModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && modal.classList.contains("is-open")) {
      closeModal();
    }
  });
});
