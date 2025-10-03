  const codeshareInput = document.getElementById("codeshareInput");
  const codeshareResults = document.getElementById("codeshareResults");
  const codeshareTitle = document.getElementById("codeshareTitle");
  const codeshareCode = document.getElementById("codeshareCode");
  const codeshareLink = document.getElementById("codeshareLink");
  const codeshareModal = document.getElementById("codeshareModal");

  let debounce;
  codeshareInput.addEventListener("input", () => {
    clearTimeout(debounce);
    const query = codeshareInput.value.trim();
    if (query.length < 2) {
      codeshareResults.innerHTML = "";
      codeshareModal.style.display = "none";
      return;
    }
    debounce = setTimeout(() => searchCodeshare(query), 300);
  });

  async function searchCodeshare(query) {
    const res = await fetch(`/search?q=${encodeURIComponent(query)}`);
    const data = await res.json();
    codeshareResults.innerHTML = "";

    if (data.length === 0) {
      codeshareResults.innerHTML = "<div class='text-muted'>No results found.</div>";
      return;
    }

    data.forEach(item => {
      const div = document.createElement("div");
      div.className = "border p-2 mb-2 rounded bg-light text-dark";
      div.style.cursor = "pointer";
      div.innerHTML = `<strong>${item.title}</strong><br><small>${item.preview}</small>`;
      div.onclick = () => showSnippet(item.id, item.title, item.url);
      codeshareResults.appendChild(div);
    });
  }

  async function showSnippet(id, title, url) {
    const res = await fetch(`/snippet/${id}`);
    const data = await res.json();
    codeshareTitle.textContent = title;
    codeshareCode.value = data.code;
    codeshareLink.href = url;
    codeshareModal.style.display = "block";
  }