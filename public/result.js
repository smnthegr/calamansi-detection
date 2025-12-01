// Disease information with detailed descriptions and treatments
const diseaseInfo = {
  'black spot': {
    name: 'Black Spot Disease',
    description: 'Black spot is a fungal disease that causes dark spots on leaves and fruits. It thrives in warm, humid conditions. Treatment: Remove affected leaves, improve air circulation, apply copper-based fungicides, and avoid overhead watering.'
  },
  'canker': {
    name: 'Citrus Canker',
    description: 'Citrus canker is a bacterial disease causing raised lesions on leaves, stems, and fruit. It spreads rapidly in wet conditions. Treatment: Remove and destroy infected plant parts, apply copper sprays, quarantine affected plants, and practice good sanitation.'
  },
  'greening': {
    name: 'Citrus Greening (Huanglongbing)',
    description: 'Citrus greening is a serious bacterial disease transmitted by psyllids. It causes yellowing of leaves, stunted growth, and bitter fruit. Treatment: Remove infected trees immediately, control psyllid populations with insecticides, and plant disease-free nursery stock.'
  },
  'healthy calamansi': {
    name: 'Healthy Calamansi',
    description: 'This calamansi appears healthy with no visible signs of disease. Continue regular care: proper watering, fertilization, pruning, and monitoring for early signs of pests or diseases to maintain plant health.'
  },
  'scab': {
    name: 'Citrus Scab',
    description: 'Citrus scab is a fungal disease causing raised, corky lesions on fruit and leaves. It affects young tissue during wet weather. Treatment: Apply copper fungicides during early growth stages, improve drainage, prune to increase air circulation, and remove infected fruit.'
  },
  'thrips': {
    name: 'Thrips Damage',
    description: 'Thrips are tiny insects that cause silvery streaks, distorted leaves, and scarred fruit. They thrive in hot, dry conditions. Treatment: Use insecticidal soaps or neem oil, introduce beneficial insects, maintain proper moisture levels, and remove heavily infested plant parts.'
  }
};

// Function to draw image with bounding box
function drawImageWithBoundingBox(imageSrc, boundingBox, confidence, diseaseClass, originalWidth, originalHeight) {
  const canvas = document.getElementById('resultCanvas');
  const ctx = canvas.getContext('2d');
  const img = new Image();
  
  img.onload = function() {
    // Set canvas size to match image
    canvas.width = img.width;
    canvas.height = img.height;
    
    // Draw the image
    ctx.drawImage(img, 0, 0);
    
    // Calculate scaling factor (Roboflow coordinates are based on original image size)
    const scaleX = img.width / originalWidth;
    const scaleY = img.height / originalHeight;
    
    // Convert center coordinates to top-left corner coordinates and scale
    const x = (boundingBox.x - boundingBox.width / 2) * scaleX;
    const y = (boundingBox.y - boundingBox.height / 2) * scaleY;
    const width = boundingBox.width * scaleX;
    const height = boundingBox.height * scaleY;
    
    // Draw bounding box
    ctx.strokeStyle = '#00FF00'; // Green color
    ctx.lineWidth = 3;
    ctx.strokeRect(x, y, width, height);
    
    // Draw semi-transparent background for label
    ctx.fillStyle = 'rgba(0, 255, 0, 0.7)';
    const labelText = `${diseaseClass} (${confidence}%)`;
    ctx.font = 'bold 16px Arial';
    const textWidth = ctx.measureText(labelText).width;
    ctx.fillRect(x, y - 25, textWidth + 10, 25);
    
    // Draw label text
    ctx.fillStyle = '#000000';
    ctx.fillText(labelText, x + 5, y - 7);
  };
  
  img.src = imageSrc;
}

// Load and display results
window.addEventListener('DOMContentLoaded', function() {
  console.log('Result page loaded, checking for data...');
  
  // Get results from sessionStorage
  const resultData = sessionStorage.getItem('detectionResult');
  
  if (!resultData) {
    console.error('No result data found in sessionStorage');
    alert('No detection results found. Redirecting to home page.');
    window.location.href = 'index.html';
    return;
  }
  
  const result = JSON.parse(resultData);
  console.log('Full Result Data:', result);
  
  // Validate result structure
  if (!result.model1 || !result.model2) {
    console.error('Invalid result structure:', result);
    alert('Invalid result data. Please try again.');
    window.location.href = 'index.html';
    return;
  }
  
  // Display verification badge
  const verificationBadge = document.getElementById('verificationBadge');
  if (verificationBadge) {
    verificationBadge.style.display = 'block';
    verificationBadge.textContent = `✓ Verified as Calamansi (${result.model1.confidence}%)`;
  }
  
  // Get disease info
  const classKey = result.model2.class.toLowerCase();
  const info = diseaseInfo[classKey] || {
    name: result.model2.class,
    description: 'Disease detected. Please consult with an agricultural expert for proper diagnosis and treatment.'
  };
  
  console.log('Disease detected:', info.name);
  console.log('Confidence:', result.model2.confidence + '%');
  
  // Draw image with bounding box
  if (result.imageSrc && result.model2.boundingBox) {
    drawImageWithBoundingBox(
      result.imageSrc,
      result.model2.boundingBox,
      result.model2.confidence,
      info.name,
      result.imageWidth,
      result.imageHeight
    );
  } else {
    console.error('Missing image or bounding box data');
  }
  
  // Display the results
  const diseaseNameEl = document.getElementById('diseaseName');
  const confidenceEl = document.getElementById('confidence');
  const descriptionEl = document.getElementById('description');
  
  if (diseaseNameEl) diseaseNameEl.textContent = info.name;
  if (confidenceEl) confidenceEl.textContent = result.model2.confidence + '%';
  if (descriptionEl) descriptionEl.textContent = info.description;
  
  // Log all predictions for debugging
  if (result.allPredictions) {
    console.log('All disease detections:', result.allPredictions);
  }
});