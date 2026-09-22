/**
 * Modern Drag and Drop file upload with step-by-step progress tracking.
 */

document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('fileUploadInput');
    const uploadForm = document.getElementById('uploadForm');
    const progressPanel = document.getElementById('progressPanel');
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
});
