// API Configuration
const API_BASE_URL = window.location.origin;

// Validation constants
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const MIN_IMAGE_SIZE = 100; // pixels
const MAX_IMAGE_SIZE = 4096; // pixels

// DOM elements
const fileInput = document.getElementById('fileInput');
const detectBtn = document.getElementById('detectBtn');
const imagePreview = document.getElementById('imagePreview');
const previewImg = document.getElementById('previewImg');
const uploadForm = document.getElementById('uploadForm');

let currentImageUrl = null;
let currentFile = null;

fileInput.addEventListener('change', function(e) {
  const file = e.target.files[0];
  
  if (file) {
    const validation = validateFile(file);
    if (!validation.valid) {
      alert(validation.error);
      fileInput.value = '';
      return;
    }
    
    currentFile = file;
    loadImagePreview(file);
    detectBtn.disabled = false;
  }
});

function validateFile(file) {
  if (file.size > MAX_FILE_SIZE) {
    return {
      valid: false,
      error: 'File size exceeds 10MB. Please choose a smaller image.'
    };
  }
  
  if (!ALLOWED_TYPES.includes(file.type)) {
    return {
      valid: false,
      error: 'Invalid file type. Please upload a JPEG, PNG, or WebP image.'
    };
  }
  
  return { valid: true };
}

function loadImagePreview(file) {
  if (currentImageUrl) {
    URL.revokeObjectURL(currentImageUrl);
  }
  
  currentImageUrl = URL.createObjectURL(file);
  
  const img = new Image();
  img.onload = function() {
    if (img.width < MIN_IMAGE_SIZE || img.height < MIN_IMAGE_SIZE) {
      alert(`Image is too small (${img.width}x${img.height}). Minimum size is ${MIN_IMAGE_SIZE}x${MIN_IMAGE_SIZE} pixels.`);
      fileInput.value = '';
      URL.revokeObjectURL(currentImageUrl);
      currentImageUrl = null;
      detectBtn.disabled = true;
      return;
    }
    
    if (img.width > MAX_IMAGE_SIZE || img.height > MAX_IMAGE_SIZE) {
      alert(`Image is too large (${img.width}x${img.height}). Maximum size is ${MAX_IMAGE_SIZE}x${MAX_IMAGE_SIZE} pixels.`);
      fileInput.value = '';
      URL.revokeObjectURL(currentImageUrl);
      currentImageUrl = null;
      detectBtn.disabled = true;
      return;
    }
    
    previewImg.src = currentImageUrl;
    previewImg.alt = `Preview of ${file.name}`;
    imagePreview.classList.add('show');
  };
  
  img.onerror = function() {
    alert('Failed to load image. The file may be corrupted.');
    fileInput.value = '';
    URL.revokeObjectURL(currentImageUrl);
    currentImageUrl = null;
    detectBtn.disabled = true;
  };
  
  img.src = currentImageUrl;
}

uploadForm.addEventListener('submit', async function(e) {
  e.preventDefault();
  
  if (!currentFile) {
    alert('Please select an image first');
    return;
  }
  
  await processDetection();
});

async function processDetection() {
  setLoadingState(true, 'Analyzing image...');
  
  try {
    // Prepare FormData
    const formData = new FormData();
    formData.append('image', currentFile);
    
    // Make API request to backend
    const response = await fetch(`${API_BASE_URL}/api/detect`, {
      method: 'POST',
      body: formData
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      // Handle different error types
      if (response.status === 429) {
        throw new Error('Too many detection attempts. Please wait a moment and try again.');
      }
      
      if (response.status === 400 && data.type === 'validation_error') {
        throw new Error(data.error);
      }
      
      throw new Error(data.error || 'Detection failed. Please try again.');
    }
    
    // Store result in sessionStorage (matching result.html format)
    const resultData = {
      model1: {
        class: data.model1.class,
        confidence: data.model1.confidence.toString()
      },
      model2: {
        class: data.model2.class,
        confidence: data.model2.confidence.toString(),
        boundingBox: data.model2.boundingBox
      },
      imageSrc: data.imageData,
      imageWidth: data.imageWidth,
      imageHeight: data.imageHeight,
      allPredictions: data.allPredictions,
      timestamp: data.timestamp
    };
    
    console.log('Detection successful! Result:', resultData);
    sessionStorage.setItem('detectionResult', JSON.stringify(resultData));
    
    // Redirect to results page
    window.location.href = './result.html';
    
  } catch (error) {
    console.error('Detection error:', error);
    handleDetectionError(error);
  }
}

function handleDetectionError(error) {
  const errorMessage = error.message || 'An unexpected error occurred during detection.';
  
  // Check if it's a network error
  if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
    alert('Network error. Please check your internet connection and try again.');
  } else {
    alert(errorMessage);
  }
  
  resetDetectionState();
}

function setLoadingState(loading, message = '') {
  detectBtn.disabled = loading;
  fileInput.disabled = loading;
  
  if (loading) {
    detectBtn.setAttribute('aria-busy', 'true');
    detectBtn.innerHTML = `
      <span class="spinner" role="status" aria-label="Loading"></span>
      <span>${message || 'Processing...'}</span>
    `;
  } else {
    detectBtn.setAttribute('aria-busy', 'false');
    detectBtn.textContent = 'Detect Disease';
  }
}

function resetDetectionState() {
  setLoadingState(false);
}

window.addEventListener('beforeunload', function() {
  if (currentImageUrl) {
    URL.revokeObjectURL(currentImageUrl);
  }
});