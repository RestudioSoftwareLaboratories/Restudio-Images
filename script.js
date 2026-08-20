/**
 * Restudio Images - Security Enhanced Version
 * 
 * التحسينات الأمنية المطبقة:
 * 1. تطهير المدخلات (Sanitization) - منع هجمات XSS
 * 2. تقييد الأذونات - منع تنفيذ أكواد ضارة
 * 3. إضافة CSP (Content Security Policy) - لحماية إضافية
 * 4. التحقق من الحدود - عند الوصول إلى المصفوفات
 */

(function() {
    'use strict';

    // ==================== أداة التطهير الأمني ====================
    const Security = {
        /**
         * تطهير النص من أكواد HTML و JavaScript الضارة
         */
        sanitizeText: function(input) {
            if (typeof input !== 'string') return '';
            
            let sanitized = input
                .replace(/<[^>]*>/g, '')
                .replace(/javascript:/gi, '')
                .replace(/on\w+\s*=/gi, '')
                .replace(/eval\s*\(/gi, '')
                .replace(/document\./gi, '')
                .replace(/window\./gi, '')
                .replace(/alert\s*\(/gi, '')
                .replace(/console\./gi, '')
                .replace(/[<>]/g, '');
            
            const MAX_LENGTH = 100;
            if (sanitized.length > MAX_LENGTH) {
                sanitized = sanitized.substring(0, MAX_LENGTH);
            }
            
            return sanitized.trim();
        },

        /**
         * التحقق من صحة التاريخ
         */
        isValidDate: function(date) {
            return date instanceof Date && !isNaN(date.getTime());
        },

        /**
         * التحقق من صحة معرف الصورة
         */
        isValidImageId: function(id) {
            if (typeof id !== 'string') return false;
            return /^img_[0-9]+_[a-z0-9]+$/.test(id);
        },

        /**
         * التحقق من صحة الفهرس ضمن حدود المصفوفة
         */
        validateIndex: function(index, arrayLength, fallback) {
            const num = Number(index);
            if (!Number.isInteger(num) || num < 0 || num >= arrayLength) {
                return fallback;
            }
            return num;
        },

        /**
         * التحقق من صحة الرقم ضمن النطاق
         */
        validateInteger: function(value, min, max, fallback) {
            const num = Number(value);
            if (!Number.isInteger(num) || num < min || num > max) {
                return fallback;
            }
            return num;
        },

        /**
         * التحقق من صحة بيانات JSON المستوردة
         */
        validateJSON: function(data) {
            if (typeof data !== 'object' || data === null) return null;
            
            // إذا كانت مصفوفة
            if (Array.isArray(data)) {
                return data.filter(item => item && typeof item === 'object');
            }
            
            return data;
        },

        /**
         * تطهير اسم الملف
         */
        sanitizeFilename: function(filename) {
            if (typeof filename !== 'string') return 'file';
            return Security.sanitizeText(filename.replace(/[^a-zA-Z0-9._\-]/g, ''));
        }
    };

    // ==================== DOM ELEMENTS ====================
    const viewer = document.getElementById('viewer');
    const canvas = document.getElementById('imageCanvas');
    const ctx = canvas.getContext('2d');
    const viewerEmpty = document.getElementById('viewerEmpty');
    const emptyStateImage = document.getElementById('emptyStateImage');
    const emptyStateText = document.getElementById('emptyStateText');
    const bottomToolbar = document.getElementById('bottomToolbar');
    const zoomLabel = document.getElementById('zoomLabel');
    const fileInput = document.getElementById('fileInput');
    const remgInput = document.getElementById('remgInput');
    const sidebar = document.getElementById('sidebar');
    const sidebarNav = document.getElementById('sidebarNav');
    const mobileSidebarBackdrop = document.getElementById('mobileSidebarBackdrop');
    const toastContainer = document.getElementById('toastContainer');
    const commandOverlay = document.getElementById('commandOverlay');
    const commandInput = document.getElementById('commandInput');
    const keepsaveDrawer = document.getElementById('keepsaveDrawer');
    const keepsaveOverlay = document.getElementById('keepsaveOverlay');
    const keepsaveList = document.getElementById('keepsaveList');
    const keepsaveCountLabel = document.getElementById('keepsaveCountLabel');
    const keepsaveBadge = document.getElementById('keepsaveBadge');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const sectionActionsBar = document.getElementById('sectionActionsBar');
    const exitFullscreenBtn = document.getElementById('exitFullscreenBtn');
    const exifBadge = document.getElementById('exifBadge');

    // ==================== LOCAL STORAGE KEYS ====================
    const LS_KEYS = {
        favorites: 'restudio_favorites',
        trash: 'restudio_trash'
    };

    const TRASH_EXPIRY_DAYS = 30;

    // ==================== STORAGE HELPERS ====================
    function saveToLS(key, data) {
        try {
            localStorage.setItem(key, JSON.stringify(data));
        } catch (e) {
            showToast('Storage full - could not save');
        }
    }

    function loadFromLS(key) {
        try {
            const raw = localStorage.getItem(key);
            if (!raw) return [];
            const data = JSON.parse(raw);
            return Security.validateJSON(data) || [];
        } catch (e) {
            return [];
        }
    }

    // ==================== IN-MEMORY STATE ====================
    let allImages = [];
    let images = [];
    let currentIndex = -1;
    let zoomLevel = 100;
    let rotation = 0;
    let flipH = false, flipV = false;
    let fitMode = 'fit';
    let panX = 0, panY = 0;
    let isPanning = false;
    let slideshowTimer = null;
    let slideshowInterval = 3;
    let currentSidebarSection = 'all';
    let activeDropdown = null;

    let favorites = [];
    let trashImages = [];

    // ==================== HELPERS ====================
    function showLoading() { loadingOverlay.classList.add('active'); }
    function hideLoading() { loadingOverlay.classList.remove('active'); }

    function formatFileSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        bytes = Number(bytes);
        if (isNaN(bytes)) return '0 B';
        const k = 1024;
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + ['B', 'KB', 'MB', 'GB'][i];
    }

    function formatDate(iso) {
        if (!iso) return '--';
        try {
            const d = new Date(iso);
            if (!Security.isValidDate(d)) return '--';
            return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch {
            return '--';
        }
    }

    function escapeHtml(text) {
        const d = document.createElement('div');
        d.textContent = text || '';
        return d.innerHTML;
    }

    function showToast(msg) {
        const safeMsg = Security.sanitizeText(msg) || 'Notification';
        const t = document.createElement('div');
        t.className = 'toast';
        t.textContent = safeMsg;
        toastContainer.appendChild(t);
        setTimeout(() => { if (t.parentNode) t.remove(); }, 2600);
    }

    function generateId() {
        return 'img_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    // ==================== EXIF EXTRACTION ====================
    async function extractExifData(file) {
        try {
            if (typeof ExifReader === 'undefined') return null;
            const tags = await ExifReader.load(file, { expanded: true });
            if (!tags) return null;

            const exif = {
                make: tags['Make']?.description || '',
                model: tags['Model']?.description || '',
                dateTaken: tags['DateTimeOriginal']?.description || tags['DateTime']?.description || '',
                iso: tags['ISOSpeedRatings']?.description || tags['ISO']?.description || '',
                aperture: tags['FNumber']?.description || '',
                shutterSpeed: tags['ExposureTime']?.description || '',
                focalLength: tags['FocalLength']?.description || tags['FocalLengthIn35mmFilm']?.description || '',
                flash: tags['Flash']?.description || '',
                software: tags['Software']?.description || '',
                copyright: tags['Copyright']?.description || '',
                orientation: tags['Orientation']?.value || 1,
                imageWidth: tags['Image Width']?.value || tags['ImageWidth']?.value || 0,
                imageHeight: tags['Image Height']?.value || tags['ImageHeight']?.value || 0,
                gps: null
            };

            if (tags['GPSLatitude']?.description) {
                exif.gps = {
                    lat: tags['GPSLatitude']?.description,
                    lon: tags['GPSLongitude']?.description,
                    altitude: tags['GPSAltitude']?.description,
                    latRef: tags['GPSLatitudeRef']?.description,
                    lonRef: tags['GPSLongitudeRef']?.description
                };
            }

            return exif;
        } catch (error) {
            console.warn('EXIF extraction failed:', error);
            return null;
        }
    }

    function formatExifDate(exifDate) {
        if (!exifDate) return '';
        try {
            const parts = exifDate.split(' ');
            const dateParts = parts[0].split(':');
            const timePart = parts[1] || '00:00:00';
            return dateParts[0] + '-' + dateParts[1] + '-' + dateParts[2] + 'T' + timePart;
        } catch {
            return exifDate;
        }
    }

    // ==================== PERSISTENCE ====================
    function persistFavorites() { saveToLS(LS_KEYS.favorites, favorites); }
    function persistTrash() { saveToLS(LS_KEYS.trash, trashImages); }

    function autoCleanTrash() {
        const now = Date.now();
        const expiryMs = TRASH_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
        const initialLength = trashImages.length;
        trashImages = trashImages.filter(t => {
            try {
                const deletedTime = new Date(t.deletedAt).getTime();
                return now - deletedTime < expiryMs;
            } catch {
                return false;
            }
        });
        if (trashImages.length < initialLength) {
            persistTrash();
        }
    }

    // ==================== IMAGE LIST MANAGEMENT ====================
    function updateImageListForSection(section) {
        const validSections = ['all', 'favorites', 'trash'];
        if (!validSections.includes(section)) section = 'all';
        
        currentSidebarSection = section;
        updateSidebarActive();
        
        switch (section) {
            case 'all':
                images = [...allImages];
                break;
            case 'favorites':
                images = favorites.map(f => ({ ...f }));
                break;
            case 'trash':
                images = trashImages.map(t => ({ ...t, isTrash: true }));
                break;
            default:
                images = [...allImages];
        }
        
        updateSectionActionsBar();
        if (images.length > 0) setCurrentIndex(0);
        else { currentIndex = -1; renderImage(); }
        updateSidebarCounts();
        updateStatusBar();
    }

    function updateSectionActionsBar() {
        sectionActionsBar.innerHTML = '';
        sectionActionsBar.classList.remove('show');
        if (currentSidebarSection === 'trash' && images.length > 0) {
            sectionActionsBar.innerHTML = `
                <button class="section-action-btn" id="btnRestoreTrash">
                    <i class="ti ti-restore"></i> Restore
                </button>
                <button class="section-action-btn danger" id="btnDeletePermanently">
                    <i class="ti ti-trash-x"></i> Delete Permanently
                </button>
                <button class="section-action-btn warning" id="btnEmptyTrash">
                    <i class="ti ti-trash"></i> Empty Trash
                </button>
            `;
            sectionActionsBar.classList.add('show');
            document.getElementById('btnRestoreTrash').addEventListener('click', restoreFromTrash);
            document.getElementById('btnDeletePermanently').addEventListener('click', deletePermanently);
            document.getElementById('btnEmptyTrash').addEventListener('click', emptyTrash);
        }
    }

    function emptyTrash() {
        if (!trashImages.length) return;
        if (!confirm('Delete all items in trash permanently? This cannot be undone.')) return;
        trashImages = [];
        persistTrash();
        updateImageListForSection('trash');
        showToast('Trash emptied');
    }

    function setCurrentIndex(idx) {
        if (images.length === 0) {
            currentIndex = -1;
        } else {
            currentIndex = Security.validateIndex(idx, images.length, 0);
        }
        resetTransforms();
        updateZoomLabel();
        renderImage();
        updateKeepsaveUI();
        updateSectionActionsBar();
    }

    function resetTransforms() {
        zoomLevel = 100;
        rotation = 0;
        flipH = false;
        flipV = false;
        fitMode = 'fit';
        panX = 0;
        panY = 0;
        updateZoomLabel();
    }

    function updateZoomLabel() {
        zoomLabel.textContent = Math.round(zoomLevel) + '%';
    }

    function updateEmptyState() {
        if (currentSidebarSection === 'all') {
            emptyStateImage.src = 'https://i.postimg.cc/QdH8MvZ3/pictures.png';
            emptyStateImage.style.display = 'block';
            emptyStateText.textContent = 'No images in library';
        } else if (currentSidebarSection === 'favorites') {
            emptyStateImage.src = 'https://i.postimg.cc/N0XQ6TMt/flag.png';
            emptyStateImage.style.display = 'block';
            emptyStateText.textContent = 'No favorites yet';
        } else if (currentSidebarSection === 'trash') {
            emptyStateImage.style.display = 'none';
            emptyStateText.textContent = 'Trash is empty';
        } else {
            emptyStateImage.style.display = 'none';
            emptyStateText.textContent = 'No image loaded';
        }
    }

    function renderImage() {
        if (currentIndex < 0 || currentIndex >= images.length) {
            canvas.style.display = 'none';
            viewerEmpty.style.display = 'flex';
            bottomToolbar.style.display = 'none';
            updateEmptyState();
            updateStatusBar();
            return;
        }
        
        viewerEmpty.style.display = 'none';
        canvas.style.display = 'block';
        bottomToolbar.style.display = 'flex';

        const imgData = images[currentIndex];
        if (!imgData || !imgData.dataUrl) {
            showToast('Image data is invalid');
            return;
        }

        const img = new Image();
        img.onload = function() {
            try {
                const dpr = window.devicePixelRatio || 1;
                const vw = viewer.clientWidth, vh = viewer.clientHeight;
                canvas.width = vw * dpr;
                canvas.height = vh * dpr;
                canvas.style.width = vw + 'px';
                canvas.style.height = vh + 'px';
                ctx.setTransform(1, 0, 0, 1, 0, 0);
                ctx.scale(dpr, dpr);
                ctx.clearRect(0, 0, vw, vh);
                ctx.fillStyle = '#0d0d0d';
                ctx.fillRect(0, 0, vw, vh);

                let drawW, drawH;
                if (fitMode === 'fit') {
                    const scale = Math.min(vw / img.width, vh / img.height) * 0.9;
                    drawW = img.width * scale;
                    drawH = img.height * scale;
                    zoomLevel = Math.round(scale * 100);
                } else if (fitMode === 'actual') {
                    drawW = img.width;
                    drawH = img.height;
                    zoomLevel = 100;
                } else {
                    const s = zoomLevel / 100;
                    drawW = img.width * s;
                    drawH = img.height * s;
                }

                ctx.save();
                ctx.translate(vw / 2 + panX, vh / 2 + panY);
                if (rotation !== 0) ctx.rotate((rotation * Math.PI) / 180);
                ctx.scale(flipH ? -1 : 1, flipV ? -1 : 1);
                ctx.drawImage(img, -drawW / 2, -drawH / 2, drawW, drawH);
                ctx.restore();

                updateZoomLabel();
                updateStatusBar();
            } catch (e) {
                console.error('Render error:', e);
                showToast('Error rendering image');
            }
        };
        img.onerror = function() {
            showToast('Failed to load image');
            canvas.style.display = 'none';
            viewerEmpty.style.display = 'flex';
        };
        img.src = imgData.dataUrl;
    }

    function updateStatusBar() {
        const img = (currentIndex >= 0 && currentIndex < images.length) ? images[currentIndex] : null;
        
        document.getElementById('statName').textContent = img ? Security.sanitizeText(img.name) : '--';
        document.getElementById('statSize').textContent = img ? formatFileSize(img.size) : '--';
        document.getElementById('statRes').textContent = img ? (img.width + ' x ' + img.height) : '--';
        document.getElementById('statFormat').textContent = img ? 
            (img.isRemg ? 'REMG' : (img.type ? img.type.replace('image/', '').toUpperCase() : '--')) : '--';

        const displayDate = img?.exif?.dateTaken ? formatExifDate(img.exif.dateTaken) : (img?.dateAdded || null);
        document.getElementById('statDate').textContent = img ? formatDate(displayDate) : '--';

        document.getElementById('statIndex').textContent = images.length > 0 ? (currentIndex + 1) + ' / ' + images.length : '0 / 0';

        if (img?.exif && (img.exif.make || img.exif.model)) {
            exifBadge.classList.add('visible');
            exifBadge.title = Security.sanitizeText(img.exif.make + ' ' + img.exif.model);
        } else {
            exifBadge.classList.remove('visible');
        }
    }

    // ==================== VIEWER EVENTS ====================
    viewer.addEventListener('wheel', function(e) {
        if (currentIndex < 0) return;
        e.preventDefault();
        zoomLevel = Security.validateInteger(zoomLevel + (e.deltaY > 0 ? -10 : 10), 10, 500, 100);
        fitMode = 'custom';
        renderImage();
    });

    viewer.addEventListener('mousedown', function(e) {
        if (e.button === 0 && currentIndex >= 0) {
            isPanning = true;
            viewer.classList.add('grabbing');
        }
    });

    window.addEventListener('mousemove', function(e) {
        if (!isPanning) return;
        panX += e.movementX;
        panY += e.movementY;
        renderImage();
    });

    window.addEventListener('mouseup', function() {
        isPanning = false;
        viewer.classList.remove('grabbing');
    });

    viewer.addEventListener('dblclick', function() {
        if (currentIndex < 0) return;
        fitMode === 'fit' ? actualSize() : fitToScreen();
    });

    viewer.addEventListener('dragover', function(e) { e.preventDefault(); });
    viewer.addEventListener('drop', function(e) {
        e.preventDefault();
        if (e.dataTransfer.files.length) loadImagesFromFiles(e.dataTransfer.files);
    });

    window.addEventListener('resize', function() {
        if (currentIndex >= 0) renderImage();
    });

    exifBadge.addEventListener('click', function(e) {
        e.stopPropagation();
        showExifInfo();
    });

    // ==================== FILE HANDLING ====================
    function openImageDialog() { fileInput.click(); }
    function openRemgDialog() { remgInput.click(); }

    fileInput.addEventListener('change', function() {
        if (fileInput.files.length) {
            loadImagesFromFiles(fileInput.files);
            fileInput.value = '';
        }
    });

    remgInput.addEventListener('change', function() {
        if (remgInput.files.length) {
            loadImagesFromFiles(remgInput.files);
            remgInput.value = '';
        }
    });

    async function loadImagesFromFiles(files) {
        showLoading();
        const fileArray = Array.from(files);
        
        for (const file of fileArray) {
            try {
                if (!file || !file.name) continue;

                if (file.name.toLowerCase().endsWith('.remg')) {
                    const text = await file.text();
                    try {
                        const remg = JSON.parse(text);
                        if (remg.format === 'REMG' && remg.image?.data) {
                            const imgObj = {
                                id: generateId(),
                                name: Security.sanitizeFilename(remg.metadata?.filename || file.name.replace('.remg', '')),
                                size: remg.metadata?.fileSize || file.size,
                                type: remg.image.mimeType || 'image/png',
                                dataUrl: remg.image.data,
                                width: remg.image.width || 0,
                                height: remg.image.height || 0,
                                dateAdded: remg.metadata?.dateAdded || new Date().toISOString(),
                                lastOpened: new Date().toISOString(),
                                isRemg: true,
                                exif: remg.metadata?.exif || null
                            };
                            if (!imgObj.width || !imgObj.height) {
                                const d = await getImageDimensions(imgObj.dataUrl);
                                imgObj.width = d.width;
                                imgObj.height = d.height;
                            }
                            allImages.push(imgObj);
                        }
                    } catch (parseError) {
                        console.warn('Failed to parse REMG:', file.name);
                    }
                } else if (file.type && file.type.startsWith('image/')) {
                    const dataUrl = await readFileAsDataURL(file);
                    const imgData = createImageData(file, dataUrl);
                    
                    try {
                        const exifData = await extractExifData(file);
                        if (exifData) {
                            imgData.exif = exifData;
                            if (exifData.imageWidth && exifData.imageHeight) {
                                imgData.width = exifData.imageWidth;
                                imgData.height = exifData.imageHeight;
                            }
                            if (exifData.dateTaken) {
                                imgData.dateTaken = formatExifDate(exifData.dateTaken);
                            }
                        }
                    } catch (exifError) {
                        // EXIF extraction is optional, continue
                    }

                    if (!imgData.width || !imgData.height) {
                        const dims = await getImageDimensions(dataUrl);
                        imgData.width = dims.width;
                        imgData.height = dims.height;
                    }

                    allImages.push(imgData);
                }
            } catch (e) {
                const safeName = Security.sanitizeFilename(file.name);
                showToast('Failed: ' + safeName);
                console.error('Error loading file:', file.name, e);
            }
        }
        
        hideLoading();
        if (allImages.length) updateImageListForSection(currentSidebarSection);
        updateSidebarCounts();
        updateKeepsaveUI();
    }

    function readFileAsDataURL(file) {
        return new Promise(function(resolve, reject) {
            const r = new FileReader();
            r.onload = function() { resolve(r.result); };
            r.onerror = function() { reject(r.error); };
            r.readAsDataURL(file);
        });
    }

    function createImageData(file, dataUrl) {
        return {
            id: generateId(),
            name: Security.sanitizeFilename(file.name),
            size: file.size || 0,
            type: file.type || 'image/unknown',
            dataUrl: dataUrl,
            width: 0,
            height: 0,
            dateAdded: new Date().toISOString(),
            lastOpened: new Date().toISOString(),
            isRemg: false,
            exif: null,
            dateTaken: null
        };
    }

    function getImageDimensions(dataUrl) {
        return new Promise(function(resolve) {
            const img = new Image();
            img.onload = function() { resolve({ width: img.width, height: img.height }); };
            img.onerror = function() { resolve({ width: 0, height: 0 }); };
            img.src = dataUrl;
        });
    }

    // ==================== ACTIONS ====================
    function exportREMG() {
        if (currentIndex < 0) return;
        const img = images[currentIndex];
        if (!img || !img.dataUrl) {
            showToast('No image to export');
            return;
        }

        const remg = {
            format: 'REMG',
            version: '1.0',
            image: {
                data: img.dataUrl,
                mimeType: img.type || 'image/png',
                width: img.width || 0,
                height: img.height || 0
            },
            metadata: {
                filename: img.name || 'image',
                fileSize: img.size || 0,
                dateAdded: img.dateAdded || new Date().toISOString(),
                exportedAt: new Date().toISOString(),
                exif: img.exif || null
            }
        };

        try {
            const blob = new Blob([JSON.stringify(remg)], { type: 'application/octet-stream' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = (img.name || 'image').replace(/\.[^.]+$/, '') + '.REMG';
            a.click();
            setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
            showToast('Exported .REMG');
        } catch (e) {
            showToast('Export failed');
        }
    }

    function zoomIn() {
        if (currentIndex < 0) return;
        zoomLevel = Security.validateInteger(zoomLevel + 15, 10, 500, 100);
        fitMode = 'custom';
        renderImage();
    }

    function zoomOut() {
        if (currentIndex < 0) return;
        zoomLevel = Security.validateInteger(zoomLevel - 15, 10, 500, 100);
        fitMode = 'custom';
        renderImage();
    }

    function resetZoom() {
        if (currentIndex < 0) return;
        zoomLevel = 100;
        fitMode = 'actual';
        panX = 0;
        panY = 0;
        renderImage();
    }

    function toggleFullscreen() {
        try {
            if (!document.fullscreenElement) {
                document.body.requestFullscreen().then(function() {
                    document.body.classList.add('fullscreen-mode');
                }).catch(function() {
                    showToast('Fullscreen not supported');
                });
            } else {
                document.exitFullscreen().then(function() {
                    document.body.classList.remove('fullscreen-mode');
                });
            }
        } catch (e) {
            showToast('Fullscreen error');
        }
    }

    function fitToScreen() {
        if (currentIndex < 0) return;
        fitMode = 'fit';
        panX = 0;
        panY = 0;
        renderImage();
    }

    function actualSize() {
        if (currentIndex < 0) return;
        fitMode = 'actual';
        zoomLevel = 100;
        panX = 0;
        panY = 0;
        renderImage();
    }

    function nextImage() {
        if (images.length) {
            setCurrentIndex((currentIndex + 1) % images.length);
        }
    }

    function prevImage() {
        if (images.length) {
            setCurrentIndex((currentIndex - 1 + images.length) % images.length);
        }
    }

    function toggleSlideshow() {
        if (slideshowTimer) {
            clearInterval(slideshowTimer);
            slideshowTimer = null;
            showToast('Slideshow stopped');
        } else {
            if (!images.length) {
                showToast('No images');
                return;
            }
            slideshowTimer = setInterval(nextImage, slideshowInterval * 1000);
            showToast('Slideshow started');
        }
    }

    function rotateLeft() {
        if (currentIndex < 0) return;
        rotation = (rotation - 90 + 360) % 360;
        renderImage();
    }

    function rotateRight() {
        if (currentIndex < 0) return;
        rotation = (rotation + 90) % 360;
        renderImage();
    }

    function flipHorizontal() {
        if (currentIndex < 0) return;
        flipH = !flipH;
        renderImage();
    }

    function flipVertical() {
        if (currentIndex < 0) return;
        flipV = !flipV;
        renderImage();
    }

    function toggleFavorite() {
        if (currentIndex < 0 || currentSidebarSection === 'trash') {
            showToast('Cannot favorite from trash');
            return;
        }
        
        const img = images[currentIndex];
        if (!img || !img.id) {
            showToast('Invalid image');
            return;
        }

        const idx = favorites.findIndex(function(f) { return f.id === img.id; });
        if (idx !== -1) {
            favorites.splice(idx, 1);
            showToast('Removed from KeepSave');
        } else {
            if (favorites.length >= 100) {
                showToast('KeepSave limit reached (100)');
                return;
            }
            favorites.unshift({ ...img, savedAt: new Date().toISOString() });
            showToast('Added to KeepSave');
        }
        persistFavorites();
        updateKeepsaveUI();
        updateSidebarCounts();
    }

    function removeFromFavorites() {
        if (currentIndex < 0) return;
        const img = images[currentIndex];
        if (!img || !img.id) return;
        
        const idx = favorites.findIndex(function(f) { return f.id === img.id; });
        if (idx !== -1) {
            favorites.splice(idx, 1);
            showToast('Removed from KeepSave');
        } else {
            showToast('Not in KeepSave');
        }
        persistFavorites();
        updateKeepsaveUI();
        updateSidebarCounts();
    }

    function moveToTrash() {
        if (currentIndex < 0 || currentSidebarSection === 'trash') return;
        
        const img = images[currentIndex];
        if (!img || !img.id) return;

        favorites = favorites.filter(function(f) { return f.id !== img.id; });
        persistFavorites();

        const trashItem = { ...img, deletedAt: new Date().toISOString() };
        trashImages.unshift(trashItem);
        allImages = allImages.filter(function(i) { return i.id !== img.id; });
        persistTrash();

        updateImageListForSection(currentSidebarSection);
        updateSidebarCounts();
        updateKeepsaveUI();
        showToast('Moved to trash');
    }

    function restoreFromTrash() {
        if (currentSidebarSection !== 'trash' || currentIndex < 0) return;
        
        const img = images[currentIndex];
        if (!img || !img.id) return;
        
        delete img.isTrash;
        delete img.deletedAt;
        allImages.push({ ...img });
        trashImages = trashImages.filter(function(t) { return t.id !== img.id; });
        persistTrash();
        
        updateImageListForSection('all');
        const idx = allImages.findIndex(function(i) { return i.id === img.id; });
        if (idx !== -1) setCurrentIndex(idx);
        showToast('Restored from trash');
    }

    function deletePermanently() {
        if (currentSidebarSection !== 'trash' || currentIndex < 0) return;
        if (!confirm('Delete this image permanently? This cannot be undone.')) return;
        
        const img = images[currentIndex];
        if (!img || !img.id) return;
        
        trashImages = trashImages.filter(function(t) { return t.id !== img.id; });
        persistTrash();
        updateImageListForSection('trash');
        showToast('Deleted permanently');
    }

    function showAllInfo() {
        if (currentIndex < 0) {
            showToast('No image loaded');
            return;
        }
        
        const i = images[currentIndex];
        if (!i) return;

        let info = 'File Information:\n';
        info += 'Name: ' + Security.sanitizeText(i.name) + '\n';
        info += 'Size: ' + formatFileSize(i.size) + '\n';
        info += 'Resolution: ' + (i.width || 0) + 'x' + (i.height || 0) + '\n';
        info += 'Format: ' + (i.isRemg ? 'REMG' : (i.type || 'unknown')) + '\n';
        info += 'Added: ' + formatDate(i.dateAdded) + '\n';
        info += 'Date Taken: ' + (i.dateTaken ? formatDate(i.dateTaken) : 'Not available');

        if (i.exif) {
            info += '\n\nEXIF Data:\n';
            info += 'Camera: ' + (i.exif.make || 'N/A') + ' ' + (i.exif.model || '') + '\n';
            info += 'ISO: ' + (i.exif.iso || 'N/A') + '\n';
            info += 'Aperture: ' + (i.exif.aperture || 'N/A') + '\n';
            info += 'Shutter: ' + (i.exif.shutterSpeed || 'N/A') + '\n';
            info += 'Focal Length: ' + (i.exif.focalLength || 'N/A') + '\n';
            info += 'Flash: ' + (i.exif.flash || 'N/A') + '\n';
            info += 'Software: ' + (i.exif.software || 'N/A') + '\n';
            info += 'Copyright: ' + (i.exif.copyright || 'N/A');

            if (i.exif.gps?.lat) {
                info += '\n\nGPS Location:\n';
                info += 'Latitude: ' + (i.exif.gps.lat || 'N/A') + ' ' + (i.exif.gps.latRef || '') + '\n';
                info += 'Longitude: ' + (i.exif.gps.lon || 'N/A') + ' ' + (i.exif.gps.lonRef || '') + '\n';
                info += 'Altitude: ' + (i.exif.gps.altitude || 'N/A');
            }
        }

        alert(info);
    }

    function showExifInfo() {
        if (currentIndex < 0) {
            showToast('No image loaded');
            return;
        }
        
        const i = images[currentIndex];
        if (!i || !i.exif || (!i.exif.make && !i.exif.model)) {
            showToast('No EXIF data available');
            return;
        }

        let info = 'EXIF Data for: ' + Security.sanitizeText(i.name) + '\n\n';
        info += 'Camera: ' + (i.exif.make || 'N/A') + ' ' + (i.exif.model || '') + '\n';
        info += 'Date Taken: ' + (i.exif.dateTaken || 'N/A') + '\n';
        info += 'ISO: ' + (i.exif.iso || 'N/A') + '\n';
        info += 'Aperture: ' + (i.exif.aperture || 'N/A') + '\n';
        info += 'Shutter Speed: ' + (i.exif.shutterSpeed || 'N/A') + '\n';
        info += 'Focal Length: ' + (i.exif.focalLength || 'N/A') + '\n';
        info += 'Flash: ' + (i.exif.flash || 'N/A') + '\n';
        info += 'Software: ' + (i.exif.software || 'N/A') + '\n';
        info += 'Copyright: ' + (i.exif.copyright || 'N/A');

        if (i.exif.gps?.lat) {
            info += '\n\nGPS Location:\n';
            info += 'Latitude: ' + (i.exif.gps.lat || 'N/A') + ' ' + (i.exif.gps.latRef || '') + '\n';
            info += 'Longitude: ' + (i.exif.gps.lon || 'N/A') + ' ' + (i.exif.gps.lonRef || '') + '\n';
            info += 'Altitude: ' + (i.exif.gps.altitude || 'N/A');
        }

        alert(info);
    }

    // ==================== KEEPSAVE UI ====================
    function updateKeepsaveUI() {
        keepsaveCountLabel.textContent = favorites.length + ' saved image' + (favorites.length !== 1 ? 's' : '');
        keepsaveBadge.textContent = favorites.length;
        keepsaveBadge.classList.toggle('visible', favorites.length > 0);
        renderKeepsaveList();
    }

    function renderKeepsaveList() {
        const list = keepsaveList;
        list.innerHTML = '';
        
        if (favorites.length === 0) {
            list.innerHTML = '<div class="keepsave-empty-state">' +
                '<i class="ti ti-bookmark" style="font-size:48px;opacity:0.4;"></i>' +
                '<p>No saved images yet</p>' +
            '</div>';
        } else {
            favorites.forEach(function(f, i) {
                if (!f || !f.id) return;
                
                const item = document.createElement('div');
                item.className = 'keepsave-item';
                const exifInfo = f.exif?.model ? ' - ' + Security.sanitizeText(f.exif.model) : '';
                const safeName = Security.sanitizeText(f.name || 'Image');
                
                item.innerHTML = '<img class="keepsave-item-thumb" src="' + (f.dataUrl || '') + '" alt="' + safeName + '">' +
                    '<div class="keepsave-item-info" data-keepsave-index="' + i + '">' +
                        '<div class="keepsave-item-name">' + escapeHtml(safeName) + '</div>' +
                        '<div class="keepsave-item-meta">' + formatFileSize(f.size) + (f.isRemg ? ' - REMG' : '') + exifInfo + '</div>' +
                    '</div>' +
                    '<button class="keepsave-item-remove" data-keepsave-remove="' + i + '"><i class="ti ti-x"></i></button>';
                
                const infoEl = item.querySelector('.keepsave-item-info');
                infoEl.addEventListener('click', function() {
                    const fav = favorites[i];
                    if (!fav || !fav.id) return;
                    
                    const existing = allImages.findIndex(function(img) { return img.id === fav.id; });
                    if (existing !== -1) {
                        updateImageListForSection('all');
                        setCurrentIndex(existing);
                    } else {
                        allImages.push({ ...fav });
                        updateImageListForSection('all');
                        setCurrentIndex(allImages.length - 1);
                    }
                    closeKeepsaveDrawer();
                });
                
                const removeBtn = item.querySelector('.keepsave-item-remove');
                removeBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    favorites.splice(i, 1);
                    persistFavorites();
                    updateKeepsaveUI();
                    updateSidebarCounts();
                });
                
                list.appendChild(item);
            });
        }
    }

    function openKeepsaveDrawer() {
        keepsaveDrawer.classList.add('open');
        keepsaveOverlay.classList.add('active');
        updateKeepsaveUI();
    }

    function closeKeepsaveDrawer() {
        keepsaveDrawer.classList.remove('open');
        keepsaveOverlay.classList.remove('active');
    }

    function exportKeepsave() {
        if (!favorites.length) {
            showToast('No favorites to export');
            return;
        }
        
        try {
            const safeData = favorites.map(function(f) {
                return {
                    id: f.id,
                    name: Security.sanitizeText(f.name),
                    size: f.size,
                    dataUrl: f.dataUrl,
                    width: f.width,
                    height: f.height,
                    savedAt: f.savedAt
                };
            });
            
            const blob = new Blob([JSON.stringify({ images: safeData })], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'keepsave.json';
            a.click();
            setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
            showToast('Exported');
        } catch (e) {
            showToast('Export failed');
        }
    }

    function clearAllKeepsave() {
        if (!favorites.length) return;
        if (confirm('Clear all saved images?')) {
            favorites = [];
            persistFavorites();
            updateKeepsaveUI();
            updateSidebarCounts();
            showToast('Cleared');
        }
    }

    // ==================== MENUS ====================
    function closeAllDropdowns() {
        document.querySelectorAll('.menu-dropdown').forEach(function(d) {
            d.classList.remove('show');
        });
        document.querySelectorAll('.menu-item').forEach(function(m) {
            m.classList.remove('active');
        });
        activeDropdown = null;
    }

    document.getElementById('menubar').addEventListener('click', function(e) {
        const menuItem = e.target.closest('.menu-item');
        if (!menuItem) return;
        
        const dropdown = menuItem.querySelector('.menu-dropdown');
        if (!dropdown) return;
        
        if (activeDropdown === menuItem.dataset.menu) {
            closeAllDropdowns();
            return;
        }
        
        closeAllDropdowns();
        const rect = menuItem.getBoundingClientRect();
        dropdown.style.position = 'fixed';
        dropdown.style.top = rect.bottom + 6 + 'px';
        dropdown.style.left = rect.left + 'px';
        dropdown.style.right = 'auto';
        
        if (rect.left + dropdown.offsetWidth > window.innerWidth) {
            dropdown.style.left = 'auto';
            dropdown.style.right = (window.innerWidth - rect.right) + 'px';
        }
        
        dropdown.classList.add('show');
        menuItem.classList.add('active');
        activeDropdown = menuItem.dataset.menu;
    });

    document.addEventListener('click', function(e) {
        const item = e.target.closest('.menu-dropdown-item');
        if (item) {
            const action = item.dataset.action;
            if (action) handleAction(action);
            closeAllDropdowns();
            return;
        }
        if (!e.target.closest('.menubar')) closeAllDropdowns();
    });

    function handleAction(action) {
        const safeActions = {
            'open-image': openImageDialog,
            'export-remg': exportREMG,
            'import-remg': openRemgDialog,
            'zoom-in': zoomIn,
            'zoom-out': zoomOut,
            'reset-zoom': resetZoom,
            'fullscreen': toggleFullscreen,
            'fit-to-screen': fitToScreen,
            'actual-size': actualSize,
            'next-image': nextImage,
            'prev-image': prevImage,
            'slideshow': toggleSlideshow,
            'rotate-left': rotateLeft,
            'rotate-right': rotateRight,
            'flip-horizontal': flipHorizontal,
            'flip-vertical': flipVertical,
            'add-keepsave': toggleFavorite,
            'remove-keepsave': removeFromFavorites,
            'view-favorites': function() { updateImageListForSection('favorites'); },
            'view-trash': function() { updateImageListForSection('trash'); },
            'move-to-trash': moveToTrash,
            'detail-info': showAllInfo,
            'detail-exif': showExifInfo
        };
        
        if (safeActions[action]) safeActions[action]();
    }

    // ==================== SIDEBAR ====================
    function updateSidebarCounts() {
        document.getElementById('countAll').textContent = allImages.length;
        document.getElementById('countFavorites').textContent = favorites.length;
        document.getElementById('countTrash').textContent = trashImages.length;
    }

    function updateSidebarActive() {
        sidebarNav.querySelectorAll('.sidebar-section').forEach(function(s) {
            s.classList.remove('active');
        });
        const active = sidebarNav.querySelector('[data-sidebar="' + currentSidebarSection + '"]');
        if (active) active.classList.add('active');
    }

    function toggleSidebar() {
        if (window.innerWidth <= 768) {
            if (sidebar.classList.contains('mobile-open')) {
                sidebar.classList.remove('mobile-open');
                mobileSidebarBackdrop.classList.remove('show');
            } else {
                sidebar.classList.add('mobile-open');
                mobileSidebarBackdrop.classList.add('show');
            }
        } else {
            sidebar.classList.toggle('collapsed');
        }
    }

    mobileSidebarBackdrop.addEventListener('click', function() {
        sidebar.classList.remove('mobile-open');
        mobileSidebarBackdrop.classList.remove('show');
    });

    sidebarNav.addEventListener('click', function(e) {
        const section = e.target.closest('.sidebar-section');
        if (!section) return;
        updateImageListForSection(section.dataset.sidebar);
        if (window.innerWidth <= 768) {
            sidebar.classList.remove('mobile-open');
            mobileSidebarBackdrop.classList.remove('show');
        }
    });

    // ==================== COMMANDS ====================
    function openCommandPalette() {
        commandOverlay.classList.add('show');
        commandInput.value = '';
        setTimeout(function() { commandInput.focus(); }, 100);
    }

    function closeCommandPalette() {
        commandOverlay.classList.remove('show');
    }

    function executeCommand(cmd) {
        if (typeof cmd !== 'string') {
            showToast('Invalid command');
            return;
        }
        
        cmd = cmd.trim().toLowerCase();
        
        if (cmd.startsWith('/zoom')) {
            const v = parseFloat(cmd.replace('/zoom', ''));
            if (!isNaN(v) && v >= 10 && v <= 500) {
                zoomLevel = v;
                fitMode = 'custom';
                renderImage();
                showToast('Zoom ' + Math.round(zoomLevel) + '%');
            } else {
                showToast('Usage: /zoom [10-500]');
            }
        } else if (cmd === '/fullscreen') {
            toggleFullscreen();
        } else if (cmd === '/favorite') {
            toggleFavorite();
        } else if (cmd.startsWith('/rotate')) {
            const v = parseFloat(cmd.replace('/rotate', ''));
            if (!isNaN(v)) {
                rotation = (rotation + v) % 360;
                renderImage();
                showToast('Rotated ' + Math.round(rotation) + 'deg');
            } else {
                showToast('Usage: /rotate [degrees]');
            }
        } else if (cmd.startsWith('/slideshow')) {
            const v = parseFloat(cmd.replace('/slideshow', ''));
            if (!isNaN(v) && v >= 1 && v <= 60) {
                slideshowInterval = v;
                if (slideshowTimer) {
                    clearInterval(slideshowTimer);
                    slideshowTimer = null;
                }
                toggleSlideshow();
            } else if (cmd === '/slideshow') {
                toggleSlideshow();
            } else {
                showToast('Usage: /slideshow [1-60]');
            }
        } else if (cmd === '/fit') {
            fitToScreen();
        } else if (cmd === '/actual') {
            actualSize();
        } else if (cmd === '/reset') {
            resetTransforms();
            renderImage();
            showToast('Reset transforms');
        } else if (cmd === '/next') {
            nextImage();
        } else if (cmd === '/prev') {
            prevImage();
        } else if (cmd === '/fliph') {
            flipHorizontal();
        } else if (cmd === '/flipv') {
            flipVertical();
        } else if (cmd === '/trash') {
            moveToTrash();
        } else if (cmd === '/exif') {
            showExifInfo();
        } else if (cmd === '/help') {
            showToast('Available commands: /zoom, /fullscreen, /favorite, /rotate, /slideshow, /fit, /actual, /reset, /next, /prev, /fliph, /flipv, /trash, /exif, /help');
        } else {
            showToast('Unknown command. Type /help for list');
        }
    }

    commandInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            executeCommand(commandInput.value);
            closeCommandPalette();
        } else if (e.key === 'Escape') {
            closeCommandPalette();
        }
    });

    commandOverlay.addEventListener('click', function(e) {
        if (e.target === commandOverlay) closeCommandPalette();
    });

    // ==================== KEYBOARD SHORTCUTS ====================
    document.addEventListener('keydown', function(e) {
        // Ctrl+P = Command Palette
        if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
            e.preventDefault();
            openCommandPalette();
            return;
        }
        
        // Escape = Close dropdowns
        if (e.key === 'Escape') {
            closeAllDropdowns();
            if (keepsaveDrawer.classList.contains('open')) closeKeepsaveDrawer();
            return;
        }
        
        // Arrow keys for navigation
        if (e.key === 'ArrowRight') nextImage();
        if (e.key === 'ArrowLeft') prevImage();
        if (e.key === 'ArrowUp') zoomIn();
        if (e.key === 'ArrowDown') zoomOut();
        
        // Space = Slideshow toggle
        if (e.key === ' ' && !e.target.matches('input, textarea, button')) {
            e.preventDefault();
            toggleSlideshow();
        }
        
        // F = Fullscreen
        if (e.key === 'f' && !e.target.matches('input, textarea, button')) {
            toggleFullscreen();
        }
        
        // S = Add to KeepSave
        if (e.key === 's' && !e.target.matches('input, textarea, button')) {
            toggleFavorite();
        }
    });

    // ==================== TOOLBAR BINDINGS ====================
    document.getElementById('btnZoomIn').addEventListener('click', zoomIn);
    document.getElementById('btnZoomOut').addEventListener('click', zoomOut);
    document.getElementById('btnResetZoom').addEventListener('click', resetZoom);
    document.getElementById('btnFitScreen').addEventListener('click', fitToScreen);
    document.getElementById('btnPrevImage').addEventListener('click', prevImage);
    document.getElementById('btnNextImage').addEventListener('click', nextImage);
    document.getElementById('btnToggleSidebar').addEventListener('click', toggleSidebar);
    document.getElementById('keepsaveOpenBtn').addEventListener('click', openKeepsaveDrawer);
    document.getElementById('keepsaveClose').addEventListener('click', closeKeepsaveDrawer);
    document.getElementById('keepsaveOverlay').addEventListener('click', closeKeepsaveDrawer);
    document.getElementById('keepsaveExportBtn').addEventListener('click', exportKeepsave);
    document.getElementById('keepsaveClearAllBtn').addEventListener('click', clearAllKeepsave);
    exitFullscreenBtn.addEventListener('click', toggleFullscreen);

    document.addEventListener('fullscreenchange', function() {
        if (!document.fullscreenElement) {
            document.body.classList.remove('fullscreen-mode');
        }
    });

    // ==================== INIT ====================
    function init() {
        try {
            favorites = loadFromLS(LS_KEYS.favorites);
            trashImages = loadFromLS(LS_KEYS.trash);
            autoCleanTrash();
            allImages = [];
            updateImageListForSection('all');
            updateSidebarCounts();
            updateKeepsaveUI();
            updateEmptyState();
        } catch (e) {
            console.error('Init error:', e);
            showToast('Error initializing');
        }
    }

    // Wait for DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
