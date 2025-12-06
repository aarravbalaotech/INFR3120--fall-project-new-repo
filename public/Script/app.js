
// IIFE
(function () {
  function start() {
    console.log("App started...");
  }
  window.addEventListener("load", start);
})();

function openProfileModal() {
  const modal = document.getElementById("profileModal");
  if (modal) modal.classList.remove("hidden");
}

function closeProfileModal() {
  const modal = document.getElementById("profileModal");
  if (modal) modal.classList.add("hidden");
}

  