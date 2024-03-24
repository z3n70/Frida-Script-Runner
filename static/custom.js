var socket = io.connect("http://" + document.domain + ":" + location.port);

var logOutput = document.getElementById("outputFrida");
var runButton = document.getElementById("runBtn");
var stopButton = document.getElementById("stopBtn");
runButton.disabled = false;
stopButton.disabled = true;

socket.on("output", function (data) {
  var outputList = document.getElementById("output-list");
  var listItem = document.createElement("li");
  listItem.appendChild(document.createTextNode(`${data.data}`));
  outputList.appendChild(listItem);
});

function toggleCustomScript() {
  var customScriptCheckbox = document.getElementById("customScriptCheckbox");
  var useCustomScriptInput = document.getElementById("useCustomScript");

  if (customScriptCheckbox.checked) {
    useCustomScriptInput.value = "1";
  } else {
    useCustomScriptInput.value = "0";
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
  logOutput.innerHTML = '<ul id="output-list"></ul>';
  fetch("/stop-frida")
    .then((response) => response.text())
    .then((data) => {
      document.getElementById(
        "outputContainer"
      ).innerHTML += `</br><span>Log:  ${data}</span>`;
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
  event.preventDefault();
  runButton.disabled = true;
  stopButton.disabled = false;
  runFrida();
});

function runFrida() {
  const form = document.querySelector("form");
  const outputContainer = document.getElementById("outputContainer");
  logOutput.innerHTML = '<ul id="output-list"></ul>';

  const formData = new FormData(form);
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
      appendContent(`</br><span>Error: ${error.message}</span`);
    });
}
function appendContent(content) {
  const outputContainer = document.getElementById("outputContainer");
  outputContainer.innerHTML += `Log: ${content}`;
  outputContainer.scrollTop = outputContainer.scrollHeight;
}
runFrida();
