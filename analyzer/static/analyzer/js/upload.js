/**
 * Modern Drag and Drop file upload with step-by-step progress tracking.
 */

document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('fileUploadInput');
    const uploadForm = document.getElementById('uploadForm');
    const fileSelectedInfo = document.getElementById('fileSelectedInfo');

    if (!dropzone || !fileInput) return;

    // Dropzone drag events
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        });
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files;
            displayFileInfo(files[0]);
        }
    });

    dropzone.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            displayFileInfo(fileInput.files[0]);
        }
    });

    function displayFileInfo(file) {
        if (!fileSelectedInfo) return;
        const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
        fileSelectedInfo.innerHTML = `
            <div style="margin-top: 14px; padding: 12px; background: rgba(59, 130, 246, 0.1); border: 1px solid var(--border-highlight); border-radius: var(--radius-sm); text-align: left; display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <span style="font-weight: 600; color: #fff;">${file.name}</span>
                    <span style="font-size: 0.8rem; color: var(--text-dim); margin-left: 8px;">(${sizeMb} MB)</span>
                </div>
                <span class="cat-badge" style="background: #10b981; color: #fff; border: none;">READY</span>
            </div>
        `;
    }

    if (uploadForm) {
        uploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const file = fileInput.files[0];
            if (!file) {
                alert("PLEASE SELECT A FILE TO ANALYZE! // ファイルを選択してください");
                return;
            }

            const submitBtn = uploadForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> UPLOADING &amp; ANALYZING...';
            }

            const formData = new FormData(uploadForm);
            const xhr = new XMLHttpRequest();
            xhr.open('POST', uploadForm.action || window.location.href, true);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

            xhr.upload.onprogress = (evt) => {
                if (evt.lengthComputable && submitBtn) {
                    const pct = Math.round((evt.loaded / evt.total) * 50);
                    submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> UPLOADING (${pct}%)...`;
                    if (evt.loaded === evt.total) {
                        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> DECOMPILING &amp; EXTRACTING...';
                    }
                }
            };

            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    if (submitBtn) submitBtn.innerHTML = '<i class="bi bi-check2-circle me-2"></i> COMPLETE! REDIRECTING...';
                    try {
                        const data = JSON.parse(xhr.responseText);
                        if (data.redirect_url) {
                            window.location.href = data.redirect_url;
                            return;
                        }
                    } catch (ex) {}
                    window.location.href = '/';
                } else {
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = '<i class="bi bi-exclamation-triangle-fill me-2"></i> ERROR - RETRY';
                    }
                    alert("Analysis error: " + (xhr.responseText || "Server failed to process file."));
                }
            };

            xhr.onerror = () => {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="bi bi-exclamation-triangle-fill me-2"></i> RETRY';
                }
                alert("Network error occurred during upload.");
            };

            xhr.send(formData);
        });
    }
});
