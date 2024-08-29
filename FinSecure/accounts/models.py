from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class Personal(models.Model):
    MARITAL_STATUS_CHOICES = [
        ('Single', 'Single'),
        ('Married', 'Married'),
        ('Divorced', 'Divorced'),
        ('Widowed', 'Widowed'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)
    email = models.EmailField()
    phone = models.CharField(max_length=10)
    age = models.IntegerField()
    retirement_age = models.IntegerField()
    marital_status = models.CharField(max_length=20, choices=MARITAL_STATUS_CHOICES)
    dependents = models.IntegerField()

    def __str__(self):
        return self.user.username
    
class income(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    monthly_income = models.IntegerField()
    other_sources = models.IntegerField()
    expected_salary_growth = models.IntegerField()
    employment_type = models.CharField(max_length=10)
    employer_contributions = models.IntegerField()
    def __str__(self):
        return self.user.username
    
class expenses(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    monthly_expenses = models.IntegerField()
    annual_expenses = models.IntegerField()
    one_time_expenses = models.IntegerField()
    debt = models.IntegerField()
    def __str__(self):
        return self.user.username
    

class savings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    current_savings = models.IntegerField()
    retirement_savings = models.IntegerField()
    investments = models.IntegerField()
    return_on_investments = models.IntegerField()
    def __str__(self):
        return self.user.username
    

class assets(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    real_estates = models.IntegerField()
    vehicles = models.IntegerField()
    liabilities = models.IntegerField()
    other_assets = models.IntegerField()
    def __str__(self):
        return self.user.username
    
class financial_goals(models.Model):
    RETIREMENT_LIFESTYLE_CHOICES=[
        ('luxurious', 'Luxurious'),
        ('comfortable', 'Comfortable'),
        ('moderate', 'Moderate'),
        ('frugal', 'Frugal')
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    retirement_lifestyle = models.CharField(max_length=20, choices=RETIREMENT_LIFESTYLE_CHOICES)
    def __str__(self):
        return self.user.username
    
class risk_profile(models.Model):
    RISK_TOLERANCE_CHOICES=[
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low')
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    risk_tolerance = models.CharField(max_length=10, choices=RISK_TOLERANCE_CHOICES)
    def __str__(self):
        return self.user.username