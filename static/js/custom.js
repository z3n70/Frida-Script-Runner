// var socket = io.connect("http://" + document.domain + ":" + location.port);
var socket = io.connect(window.location.protocol + '//' + window.location.hostname + ':' + window.location.port);

var logOutput = document.getElementById("outputFrida");
var runButton = document.getElementById("runBtn");
var stopButton = document.getElementById("stopBtn");

runButton.disabled = false;
stopButton.disabled = true;

socket.on('connected', function(data){
  console.log(data)
})
socket.on("output", function (data) {
  var outputList = document.getElementById("output-list");
  var listItem = document.createElement("pre");
  listItem.appendChild(document.createTextNode(`${data.data}`));
  outputList.appendChild(listItem);
});

function toggleCustomScript() {
  var customScriptCheckbox = document.getElementById("customScriptCheckbox");
  var useCustomScriptInput = document.getElementById("useCustomScript");

  if (customScriptCheckbox.checked) {
    customScriptCheckbox.value = "1";
  } else {
    customScriptCheckbox.value = "0";
  }
}

function filterOptions() {
  var input, filter, select, option, i, txtValue;
  input = document.getElementById("searchInput");
  filter = input.value.toUpperCase();
  select = document.getElementById("packageSelect");
  options = select.getElementsByTagName("option");

  for (i = 0; i < options.length; i++) {
    txtValue = options[i].textContent || options[i].innerText;
    if (txtValue.toUpperCase().indexOf(filter) > -1) {
      options[i].style.display = "";
    } else {
      options[i].style.display = "none";
    }
  }
}

var bypassScript = document.getElementById("selectedScript");
bypassScript.addEventListener("change", function () {
  updateTextArea();
});

function updateTextArea() {
  var select = document.getElementById("selectedScript");
  var scriptContentTextArea = document.getElementById("scriptContent");
  var selectedScript = select.options[select.selectedIndex].value;

  fetch(`/get-script-content?script=${selectedScript}`)
    .then((response) => {
      if (!response.ok) {
        throw new Error("Script content not found");
      }
      return response.text();
    })
    .then((data) => (scriptContentTextArea.value = data))
    .catch((error) => {
      scriptContentTextArea.value = `Error loading script content: ${error.message}`;
      console.error(error);
    });
}

stopButton.addEventListener("click", function (event) {
  event.preventDefault();
  stopButton.disabled = true;
  runButton.disabled = false;
  var clearOutput = document.getElementById("clearOutput")
  clearOutput.innerHTML = ""
  clearOutput.innerHTML = `<p class="wraptext" id="outputFrida"></p><div id="output-list"></div>`
  logOutput.innerHTML =
    '</br><span class="text-success">~</span><pre class="wraptext" id="output-list"></pre>';
  fetch("/stop-frida")
    .then((response) => response.text())
    .then((data) => {
      document.getElementById(
        "outputContainer"
      ).innerHTML += `</br><pre class="wraptext"> ${data}</pre>`;
    })
    .catch((error) => console.error(error));
});
// function stopFrida() {
//     preventDefault();
//     stopButton.disabled = true;
//     runButton.disabled = false;
//     logOutput.innerHTML = '<ul id="output-list"></ul>';
//     fetch('/stop-frida')
//         .then(response => response.text())
//         .then(data => {
//             document.getElementById("outputContainer").innerHTML += '<div class="alert alert-info mt-4"><h2>Result:</h2><p>' + data + '</p></div>';
//         })
//         .catch(error => console.error(error));
// }

runButton.addEventListener("click", function (event) {
  var clearOutput = document.getElementById("clearOutput")
  clearOutput.innerHTML = `<p class="wraptext" id="outputFrida"></p><div id="output-list"></div>`
  event.preventDefault();
  runButton.disabled = true;
  stopButton.disabled = false;
  runFrida();
});

function runFrida() {
  const form = document.querySelector("form");
  const outputContainer = document.getElementById("outputContainer");
  logOutput.innerHTML = '</br><pre class="wraptext"></pre>';

  const formData = new FormData(form);
  const packageValue = formData.get('package');
  if (packageValue.includes('----')){
    alert('Please select the package');
    runButton.disabled = false;
    stopButton.disabled = true;
    return
  }
  fetch("/run-frida", {
    method: "POST",
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      const content = data.result || data.error || "Unknown error occurred";
      appendContent(content);
    })
    .catch((error) => {
      console.error(error);
      appendContent(
        `</br><span class="text-success">~</span><pre class="wraptext">Error: ${error.message}</pre>`
      );
    });
}
function appendContent(content) {
  const outputContainer = document.getElementById("outputContainer");
  outputContainer.innerHTML += `<span class="text-success">~</span> ${content} </br>`;
  outputContainer.scrollTop = outputContainer.scrollHeight;
}
// modal(); pada codeshare search
document.addEventListener("DOMContentLoaded", function () {
  const mainInput = document.getElementById("codeshareSearchInput");
  const modalInput = document.getElementById("modalSearchInput");
  const modalResultsDiv = document.getElementById("modalResults");
  const modalEl = document.getElementById("codeshareResultsModal");
  const bsModal = new bootstrap.Modal(modalEl);

  function performSearch(keyword) {
    if (!keyword) {
      modalResultsDiv.innerHTML = "<p>No search keyword.</p>";
      return;
    }

    fetch(`/codeshare/search?keyword=${encodeURIComponent(keyword)}`)
      .then(res => res.json())
      .then(data => {
        modalResultsDiv.innerHTML = "";

        if (data.length === 0) {
          modalResultsDiv.innerHTML = "<p>No results found.</p>";
          return;
        }

        const list = document.createElement("ul");
        list.className = "list-group";

        data.forEach(item => {
          const li = document.createElement("li");
          li.className = "list-group-item";
          li.style.cursor = "pointer";
          li.innerHTML = `<h5>${item.title}</h5><a href="${item.source}" target="_blank" class="text-decoration-none d-block small text-muted">${item.source}</a><p>${item.preview}</p>`;
          li.onclick = () => {document.getElementById("scriptContent").value = item.script;
            bsModal.hide();
            setTimeout(() => {
              document.querySelectorAll(".modal-backdrop").forEach(el => el.remove());
              document.body.classList.remove("modal-open");
            }, 300); 
          };
          list.appendChild(li);
        });
        modalResultsDiv.appendChild(list);
      });
  }

  mainInput.addEventListener("input", function () {
    const keyword = mainInput.value.trim();
    if (keyword.length === 0) return;

    bsModal.show();
    modalInput.value = keyword;
    performSearch(keyword);
  });

  modalInput.addEventListener("input", function () {
    const keyword = modalInput.value.trim();
    performSearch(keyword);
  });
});